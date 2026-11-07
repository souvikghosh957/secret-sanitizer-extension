const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { ROOT } = require("./helpers");

// Minimal promise-based chrome.* mock — just enough surface for background.js
function createChrome({ local = {}, rejectMatches = [] } = {}) {
  const area = (data) => ({
    data,
    async get(keys) {
      const list = typeof keys === "string" ? [keys] : keys;
      return Object.fromEntries(list.filter(k => k in data).map(k => [k, structuredClone(data[k])]));
    },
    async set(obj) { Object.assign(data, structuredClone(obj)); },
    async remove(keys) { for (const k of [].concat(keys)) delete data[k]; },
    async setAccessLevel(opts) { this.accessLevel = opts.accessLevel; }
  });
  const registered = new Map();
  const listeners = {};
  const event = (name) => ({ addListener: (fn) => { listeners[name] = fn; } });
  return {
    listeners,
    registered,
    runtime: {
      id: "test-extension-id", onInstalled: event("installed"), onStartup: event("startup"), onMessage: event("message"),
      setUninstallURL(url) { this.uninstallUrl = url; }
    },
    storage: { local: area(local), session: area({}), onChanged: event("changed") },
    scripting: {
      async getRegisteredContentScripts() { return [...registered.values()]; },
      async unregisterContentScripts({ ids }) { ids.forEach(id => registered.delete(id)); },
      async registerContentScripts(scripts) {
        // Like Chrome: one invalid entry rejects the whole call
        for (const s of scripts) {
          if (registered.has(s.id)) throw new Error(`Duplicate script ID '${s.id}'`);
          if (s.matches.some(m => rejectMatches.includes(m))) throw new Error(`Invalid match pattern ${s.matches}`);
        }
        scripts.forEach(s => registered.set(s.id, s));
      }
    },
    alarms: {
      active: {},
      async get(name) { return this.active[name] || null; },
      create(name, info) { this.active[name] = info; },
      async clear(name) { delete this.active[name]; },
      onAlarm: event("alarm")
    },
    action: {
      badges: {},
      setBadgeText({ tabId = "global", text }) { this.badges[tabId] = text; },
      colors: {},
      setBadgeBackgroundColor({ tabId = "global", color }) { this.colors[tabId] = color; }
    },
    notifications: { sent: [], async create(id, options) { this.sent.push(options); } },
    i18n: { getMessage: (key) => key },
    permissions: { onAdded: event("permissionAdded"), onRemoved: event("permissionRemoved") },
    tabs: { open: [], async query() { return this.open; }, sendMessage: async () => {} }
  };
}

function loadBackground(options) {
  const chrome = createChrome(options);
  const context = vm.createContext({ chrome, console, crypto, URL, TextEncoder, setTimeout, clearTimeout, structuredClone });
  context.importScripts = (...files) => files.forEach(f =>
    vm.runInContext(fs.readFileSync(path.join(ROOT, f), "utf8"), context, { filename: f }));
  vm.runInContext(fs.readFileSync(path.join(ROOT, "background.js"), "utf8"), context, { filename: "background.js" });
  const send = (request, sender) => new Promise((resolve) => {
    const async = chrome.listeners.message(request, { id: "test-extension-id", ...sender }, resolve);
    if (!async) setTimeout(() => resolve(undefined), 0);
  });
  return { chrome, context, send };
}

const tab = (origin) => ({ tab: { id: 1 }, origin, url: origin + "/c/123" });
const SECRET = ["[OPENAI_KEY_k3f9_0]", "sk-proj-realsecretvalue1234567890"];

test("legacy on-disk vault and encryption flag are purged", async () => {
  const { chrome } = loadBackground({ local: { vault: { old: { replacements: "ciphertext" } }, useEncryption: true, stats: { totalBlocked: 3 } } });
  await new Promise(r => setTimeout(r, 0));
  assert.equal(chrome.storage.local.data.vault, undefined);
  assert.equal(chrome.storage.local.data.useEncryption, undefined);
  assert.equal(chrome.storage.local.data.stats.totalBlocked, 3);
  assert.equal(chrome.storage.session.accessLevel, "TRUSTED_CONTEXTS");
});

test("vault entries live in session storage and resolve only for the same origin", async () => {
  const { chrome, send } = loadBackground();
  assert.equal((await send({ action: "vault:save", replacements: [SECRET] }, tab("https://chatgpt.com"))).ok, true);

  assert.equal(chrome.storage.local.data.vault, undefined, "nothing may be written to disk");
  assert.equal(Object.keys(chrome.storage.session.data.vault).length, 1);
  assert.equal(chrome.storage.local.data.stats.totalBlocked, 1);
  assert.equal(chrome.storage.local.data.patternStats.OPENAI_KEY, 1);

  const same = await send({ action: "vault:resolve", tokens: [SECRET[0]] }, tab("https://chatgpt.com"));
  assert.deepEqual({ ...same.values }, { [SECRET[0]]: SECRET[1] });

  const other = await send({ action: "vault:resolve", tokens: [SECRET[0]] }, tab("https://evil.example"));
  assert.deepEqual({ ...other.values }, {});
});

test("expired entries never resolve", async () => {
  const { chrome, send } = loadBackground();
  await send({ action: "vault:save", replacements: [SECRET] }, tab("https://claude.ai"));
  for (const entry of Object.values(chrome.storage.session.data.vault)) entry.expires = Date.now() - 1;
  const res = await send({ action: "vault:resolve", tokens: [SECRET[0]] }, tab("https://claude.ai"));
  assert.deepEqual({ ...res.values }, {});
});

test("vault rejects malformed requests and non-tab senders", async () => {
  const { chrome, send } = loadBackground();
  const bad = [
    [{ action: "vault:save", replacements: [["not-a-placeholder", "x"]] }, tab("https://claude.ai")],
    [{ action: "vault:save", replacements: [[SECRET[0], 42]] }, tab("https://claude.ai")],
    [{ action: "vault:save", replacements: [] }, tab("https://claude.ai")],
    [{ action: "vault:save", replacements: [SECRET] }, { url: "chrome-extension://x/popup.html" }],
  ];
  for (const [req, sender] of bad) {
    assert.equal((await send(req, sender)).ok, false);
  }
  assert.equal(chrome.storage.session.data.vault, undefined);
  assert.equal(await send({ action: "vault:save", replacements: [SECRET] }, { ...tab("https://claude.ai"), id: "other-extension" }), undefined);
});

test("vault keeps at most 50 entries", async () => {
  const { chrome, send } = loadBackground();
  await Promise.all(Array.from({ length: 60 }, () =>
    send({ action: "vault:save", replacements: [SECRET] }, tab("https://claude.ai"))));
  assert.equal(Object.keys(chrome.storage.session.data.vault).length, 50);
  assert.equal(chrome.storage.local.data.stats.totalBlocked, 60);
});

test("one bad custom site cannot disable protection on other sites", async () => {
  const { chrome, context } = loadBackground({
    local: { customSites: ["good.example", "rejected.example", "javascript:alert(1)", "  Spaced.Example  "] },
    rejectMatches: ["*://rejected.example/*"]
  });
  await vm.runInContext("registerContentScripts()", context);
  const matches = [...chrome.registered.values()].flatMap(s => s.matches);
  assert.ok(matches.includes("*://chatgpt.com/*"));
  assert.ok(matches.includes("*://good.example/*"));
  assert.ok(matches.includes("*://spaced.example/*"));
  assert.ok(!matches.includes("*://rejected.example/*"));

  // Re-registering replaces everything cleanly (no duplicate-ID failures)
  await vm.runInContext("registerContentScripts(); registerContentScripts()", context);
  assert.ok([...chrome.registered.values()].every(s => s.runAt === "document_start"));
});

test("getWeekStart crosses month and year boundaries correctly", () => {
  const { context } = loadBackground();
  const weekStart = (y, m, d) => vm.runInContext(`getWeekStart(new Date(${y}, ${m}, ${d}))`, context);
  assert.equal(weekStart(2026, 9, 1), "2026-09-27");  // Thu 1 Oct 2026 → Sun 27 Sep
  assert.equal(weekStart(2027, 0, 1), "2026-12-27");  // Fri 1 Jan 2027 → Sun 27 Dec
  assert.equal(weekStart(2026, 9, 11), "2026-10-11"); // a Sunday is its own week start
});

const settle = () => new Promise(r => setTimeout(r, 5));

test("allow-list stores only salted hashes, for tab senders only", async () => {
  const { chrome, send, context } = loadBackground();
  const value = "Zq8xW3vR7tY2uI9oP4aS";
  assert.equal((await send({ action: "allow:add", values: [value] }, tab("https://claude.ai"))).ok, true);

  const { allowedValues, allowSalt } = chrome.storage.local.data;
  assert.ok(!JSON.stringify(chrome.storage.local.data).includes(value), "the value itself must never be stored");
  assert.equal(allowedValues.length, 1);
  assert.equal(allowedValues[0], context.allowedValueHash(allowSalt, value));

  await send({ action: "allow:add", values: ["another-value-entirely"] }, tab("https://claude.ai"));
  assert.equal(chrome.storage.local.data.allowSalt, allowSalt, "salt is stable");
  assert.equal(chrome.storage.local.data.allowedValues.length, 2);

  for (const [req, sender] of [
    [{ action: "allow:add", values: [] }, tab("https://claude.ai")],
    [{ action: "allow:add", values: [42] }, tab("https://claude.ai")],
    [{ action: "allow:add", values: "x" }, tab("https://claude.ai")],
    [{ action: "allow:add", values: Array(201).fill("x") }, tab("https://claude.ai")],
    [{ action: "allow:add", values: ["x"] }, { url: "chrome-extension://x/popup.html" }],
  ]) {
    assert.equal((await send(req, sender)).ok, false);
  }
  assert.equal(chrome.storage.local.data.allowedValues.length, 2);
});

test("the allow-list is capped, dropping the oldest", async () => {
  const { chrome, send } = loadBackground();
  for (let i = 0; i < 6; i++) {
    await send({ action: "allow:add", values: Array.from({ length: 100 }, (_, n) => `v${i}-${n}`) }, tab("https://claude.ai"));
  }
  assert.equal(chrome.storage.local.data.allowedValues.length, 500);
});

test("the toast can only turn off generic rules", async () => {
  const { chrome, send } = loadBackground({ local: { disabledPatterns: ["IFSC"] } });
  assert.equal((await send({ action: "rule:disable", label: "QUOTED_SECRET" }, tab("https://claude.ai"))).ok, true);
  assert.deepEqual([...chrome.storage.local.data.disabledPatterns], ["IFSC", "QUOTED_SECRET"]);
  for (const label of ["OPENAI_KEY", "PRIVATE_KEY", "PASSWORD_HINT", undefined, 42]) {
    assert.equal((await send({ action: "rule:disable", label }, tab("https://claude.ai"))).ok, false);
  }
  assert.equal(chrome.storage.local.data.disabledPatterns.length, 2);
});

test("pausing shows on the badge and sets an expiry alarm; resuming clears both", async () => {
  const { chrome } = loadBackground({ local: { stats: { lastDate: new Date().toDateString(), todayBlocked: 3 } } });
  await settle();
  assert.equal(chrome.action.badges.global, "3");

  const until = Date.now() + 600000;
  chrome.storage.local.data.pausedUntil = until;
  await chrome.listeners.changed({ pausedUntil: { newValue: until } }, "local");
  await settle();
  assert.equal(chrome.action.badges.global, "OFF");
  assert.equal(chrome.alarms.active.pauseEnd.when, until);

  delete chrome.storage.local.data.pausedUntil;
  await chrome.listeners.changed({ pausedUntil: { oldValue: until } }, "local");
  await settle();
  assert.equal(chrome.action.badges.global, "3");
  assert.equal(chrome.alarms.active.pauseEnd, undefined);
});

test("the pause alarm ends the pause", async () => {
  const { chrome } = loadBackground({ local: { pausedUntil: Date.now() - 1 } });
  await settle();
  assert.equal(chrome.storage.local.data.pausedUntil, undefined, "a pause that lapsed while closed is dropped");

  chrome.storage.local.data.pausedUntil = Date.now() - 1;
  await chrome.listeners.alarm({ name: "pauseEnd" });
  assert.equal(chrome.storage.local.data.pausedUntil, undefined);
});

test("pausing a site badges only that site's tabs", async () => {
  const { chrome, send } = loadBackground();
  chrome.tabs.open = [
    { id: 1, url: "https://claude.ai/chat" },
    { id: 2, url: "https://chatgpt.com/" },
    { id: 3 }, // no URL: a site we have no access to
  ];
  chrome.storage.local.data.pausedSites = ["claude.ai"];
  await chrome.listeners.changed({ pausedSites: { newValue: ["claude.ai"] } }, "local");
  await settle();
  assert.equal(chrome.action.badges[1], "OFF");
  assert.equal(chrome.action.badges[2], null, "falls back to the global badge");
  assert.ok(!(3 in chrome.action.badges));

  assert.equal(chrome.action.colors[1], "#f59e0b");

  // Chrome clears per-tab badges on navigation, so the paused page asks for its badge back
  delete chrome.action.badges[1];
  const synced = await send({ action: "badge:sync" }, { tab: { id: 1, url: "https://claude.ai/new" } });
  assert.equal(synced.ok, true);
  assert.equal(chrome.action.badges[1], "OFF");
  assert.equal((await send({ action: "badge:sync" }, {})).ok, false, "only a page can ask");

  // Resuming restores the colour as well as the text
  chrome.storage.local.data.pausedSites = [];
  await chrome.listeners.changed({ pausedSites: { newValue: [] } }, "local");
  await settle();
  assert.equal(chrome.action.badges[1], null);
  assert.equal(chrome.action.colors[1], "#0ea5e9");
});

test("browsing doesn't wake the service worker", () => {
  const { chrome } = loadBackground();
  assert.equal(chrome.tabs.onUpdated, undefined);
  assert.ok(!fs.readFileSync(path.join(ROOT, "background.js"), "utf8").includes("tabs.onUpdated"));
});

test("weekly report is opt-in for new installs and kept for people updating", async () => {
  const fresh = loadBackground();
  fresh.chrome.listeners.installed({ reason: "install" });
  await settle();
  assert.equal(fresh.chrome.storage.local.data.weeklyReport, false);
  assert.match(fresh.chrome.runtime.uninstallUrl, /^https:\/\/secretsanitizer\.com\/uninstall\.html$/);

  const updated = loadBackground();
  updated.chrome.listeners.installed({ reason: "update" });
  await settle();
  assert.equal(updated.chrome.storage.local.data.weeklyReport, true);

  const chose = loadBackground({ local: { weeklyReport: false } });
  chose.chrome.listeners.installed({ reason: "update" });
  await settle();
  assert.equal(chose.chrome.storage.local.data.weeklyReport, false, "an explicit choice survives updates");
});

test("no weekly notification unless opted in", async () => {
  const stats = { weeklyStats: { weekStart: "2020-01-05", weekBlocked: 5 }, stats: { totalBlocked: 9 } };
  const off = loadBackground({ local: { ...stats, weeklyReport: false } });
  const on = loadBackground({ local: { ...stats, weeklyReport: true } });
  const sunday = "new Date(2026, 10, 8)";
  for (const { context } of [off, on]) {
    vm.runInContext(`{ const R = Date; Date = class extends R { constructor(...a) { super(...(a.length ? a : [2026, 10, 8])); } static now() { return R.now(); } }; }`, context);
  }
  await vm.runInContext(`checkWeeklySummary(${sunday})`, off.context);
  await vm.runInContext(`checkWeeklySummary(${sunday})`, on.context);
  assert.equal(off.chrome.notifications.sent.length, 0);
  assert.equal(on.chrome.notifications.sent.length, 1);
});

test("the weekly count rolls over even while the notification is off", async () => {
  const { chrome, context } = loadBackground({
    local: { weeklyStats: { weekStart: "2020-01-05", weekBlocked: 5 }, stats: { totalBlocked: 9 }, weeklyReport: false }
  });
  vm.runInContext(`{ const R = Date; Date = class extends R { constructor(...a) { super(...(a.length ? a : [2026, 10, 8])); } static now() { return R.now(); } }; }`, context);
  await vm.runInContext("checkWeeklySummary()", context);
  assert.equal(chrome.notifications.sent.length, 0);
  assert.equal(chrome.storage.local.data.weeklyStats.weekBlocked, 0);
  assert.equal(chrome.storage.local.data.weeklyStats.weekStart, "2026-11-08");
});

test("granting a site's permission re-registers content scripts", async () => {
  const { chrome } = loadBackground({ local: { customSites: ["chat.example.ai"] } });
  chrome.listeners.permissionAdded({ origins: ["*://chat.example.ai/*"] });
  await new Promise(r => setTimeout(r, 200));
  assert.ok([...chrome.registered.values()].some(s => [...s.matches].includes("*://chat.example.ai/*")));
});

// Chrome refuses to register a content script containing a Unicode noncharacter ("isn't UTF-8
// encoded"), which turns off masking entirely, while Node runs the same file happily.
test("every shipped script is text Chrome will load", () => {
  const dirs = [ROOT, path.join(ROOT, "popup")];
  const scripts = dirs.flatMap(dir => fs.readdirSync(dir).filter(f => f.endsWith(".js")).map(f => path.join(dir, f)));
  assert.ok(scripts.length > 5);
  for (const file of scripts) {
    for (const ch of new TextDecoder("utf-8", { fatal: true }).decode(fs.readFileSync(file))) {
      const code = ch.codePointAt(0);
      assert.ok((code & 0xfffe) !== 0xfffe && (code < 0xfdd0 || code > 0xfdef), `${file} contains U+${code.toString(16)}`);
    }
  }
});

test("content scripts get the shared helpers they depend on", async () => {
  const { chrome, context } = loadBackground();
  await vm.runInContext("registerContentScripts()", context);
  const isolated = [...chrome.registered.values()].find(s => s.id === "ss-iso-defaults");
  assert.deepEqual([...isolated.js], ["i18n.js", "sites.js", "patterns.js", "detector.js", "content_script.js"]);
});
