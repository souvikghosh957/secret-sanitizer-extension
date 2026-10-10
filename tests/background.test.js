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
    runtime: { id: "test-extension-id", onInstalled: event("installed"), onStartup: event("startup"), onMessage: event("message") },
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
    alarms: { get: async () => null, create() {}, onAlarm: event("alarm") },
    action: { setBadgeText() {}, setBadgeBackgroundColor() {} },
    notifications: { create: async () => {} },
    tabs: { query: async () => [], sendMessage: async () => {} }
  };
}

function loadBackground(options) {
  const chrome = createChrome(options);
  const context = vm.createContext({ chrome, console, crypto, URL, setTimeout, clearTimeout, structuredClone });
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
