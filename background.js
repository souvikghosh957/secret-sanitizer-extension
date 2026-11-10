// background.js - Service Worker for Secret Sanitizer

importScripts("sites.js", "detector.js");

const CONTENT_SCRIPT_FILES = ["i18n.js", "sites.js", "patterns.js", "detector.js", "content_script.js"];

// A static page with no scripts or analytics; nothing about the user is put in the URL.
const UNINSTALL_URL = "https://secretsanitizer.com/uninstall.html";

function contentScriptsFor(key, matches) {
  return [
    {
      // document_start so the paste listener is registered before any page script runs
      id: `ss-iso-${key}`,
      matches,
      js: CONTENT_SCRIPT_FILES,
      runAt: "document_start"
    },
    {
      // Runs in the page's main world so it can wrap navigator.clipboard.writeText
      // before site JavaScript calls it (e.g. ChatGPT / Claude copy buttons).
      id: `ss-main-${key}`,
      matches,
      js: ["ss_clipboard_interceptor.js"],
      world: "MAIN",
      runAt: "document_start"
    }
  ];
}

// The isolated-world script does the masking; the MAIN-world one only extends Smart Restore to
// a site's copy buttons. They're registered in separate calls, so if the browser refuses the
// second (world: "MAIN" needs Chrome 111) masking still goes up.
async function registerSite(key, matches) {
  const [isolated, main] = contentScriptsFor(key, matches);
  await chrome.scripting.registerContentScripts([isolated]);
  try {
    await chrome.scripting.registerContentScripts([main]);
  } catch (err) {
    console.warn(`Copy-button restore unavailable for ${matches.join(", ")}:`, err);
  }
}

// Default sites and each custom site are registered separately: one bad entry (or a
// browser-rejected pattern) can only ever disable itself, never protection everywhere.
async function doRegisterContentScripts() {
  const registered = await chrome.scripting.getRegisteredContentScripts();
  if (registered.length > 0) {
    await chrome.scripting.unregisterContentScripts({ ids: registered.map(s => s.id) });
  }

  const { removedDefaults = [], customSites = [] } =
    await chrome.storage.local.get(["removedDefaults", "customSites"]);

  const activeDefaults = DEFAULT_SITES.filter(s => !removedDefaults.includes(s));
  if (activeDefaults.length > 0) {
    try {
      await registerSite("defaults", activeDefaults.map(siteMatchPattern));
    } catch (err) {
      console.warn("Content script registration failed for default sites:", err);
    }
  }

  const custom = Array.isArray(customSites) ? customSites : [];
  const validCustom = [...new Set(custom.map(normalizeSite).filter(Boolean))]
    .filter(s => !DEFAULT_SITES.includes(s));
  for (const [i, site] of validCustom.entries()) {
    try {
      await registerSite(`custom-${i}`, [siteMatchPattern(site)]);
    } catch (err) {
      console.warn(`Content script registration failed for ${site}:`, err);
    }
  }
}

// Serialized: install, startup and settings changes can all trigger a re-register
let registerChain = Promise.resolve();
function registerContentScripts() {
  registerChain = registerChain
    .then(doRegisterContentScripts)
    .catch(err => console.warn("Content script registration error:", err));
  return registerChain;
}

let registerTimer = null;
function debouncedRegister() {
  clearTimeout(registerTimer);
  registerTimer = setTimeout(() => registerContentScripts(), 150);
}

async function ensureAlarms() {
  // MV3 service workers can be killed at any time; re-create alarms if missing
  const [cleanup, weekly] = await Promise.all([
    chrome.alarms.get("vaultCleanup"),
    chrome.alarms.get("weeklySummary")
  ]);
  if (!cleanup) chrome.alarms.create("vaultCleanup", { periodInMinutes: 5 });
  if (!weekly)  chrome.alarms.create("weeklySummary", { periodInMinutes: 1440 });
}

// New installs opt in to the weekly notification from the popup; people updating keep it.
async function initWeeklyReportSetting(reason) {
  const { weeklyReport } = await chrome.storage.local.get("weeklyReport");
  if (typeof weeklyReport !== "boolean") {
    await chrome.storage.local.set({ weeklyReport: reason === "update" });
  }
}

chrome.runtime.onInstalled.addListener((details) => {
  registerContentScripts();
  ensureAlarms();
  initWeeklyReportSetting(details?.reason).catch(() => {});
  try {
    chrome.runtime.setUninstallURL(UNINSTALL_URL)?.catch?.(() => {});
  } catch (_) {
    // Non-critical — retried on the next update
  }
});
chrome.runtime.onStartup.addListener(() => {
  registerContentScripts();
  ensureAlarms();
  syncPauseState();
});

// A site's permission can arrive after its entry was saved (the prompt is still open at that
// point) or change from chrome://extensions, so registration follows the permission itself.
chrome.permissions.onAdded.addListener(debouncedRegister);
chrome.permissions.onRemoved.addListener(debouncedRegister);

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "vaultCleanup") {
    await cleanupVault();
    updateBadge(); // clears yesterday's count shortly after midnight
  } else if (alarm.name === "weeklySummary") {
    await checkWeeklySummary();
  } else if (alarm.name === PAUSE_ALARM) {
    await chrome.storage.local.remove("pausedUntil");
    updateBadge();
  }
});

// ==================== VAULT ====================
// Originals live only in chrome.storage.session: held in memory, never written to disk,
// cleared when the browser closes. Its default access level keeps it out of content
// scripts — they reach the vault only through the messages below, and only for entries
// created by their own site's origin.

const VAULT_TTL_MS = 15 * 60 * 1000;
const MAX_VAULT_ENTRIES = 50;
const MAX_REPLACEMENTS_PER_ENTRY = 5000;
const MAX_SECRET_LENGTH = 1024 * 1024;
const VAULT_PLACEHOLDER_RE = /^\[([A-Z][A-Z0-9_]*)_[a-z0-9]{4}_\d+\]$/;

chrome.storage.session.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => {});

// Versions before 2.3 kept the vault in chrome.storage.local (on disk) under a key derived
// from the public extension ID. Remove it, and the now-meaningless encryption toggle.
async function purgeLegacyVault() {
  try {
    await chrome.storage.local.remove(["vault", "useEncryption"]);
  } catch (_) {
    // Best effort — retried on next startup
  }
}
purgeLegacyVault();

// Serial queue for vault/stats writes to prevent read-modify-write races between tabs
let vaultChain = Promise.resolve();
function withVaultLock(fn) {
  const run = vaultChain.then(fn, fn);
  vaultChain = run.catch(() => {});
  return run;
}

function senderOrigin(sender) {
  // Only content scripts in a tab may use the vault messages
  if (!sender.tab) return null;
  if (sender.origin && sender.origin !== "null") return sender.origin;
  try {
    return new URL(sender.url).origin;
  } catch (_) {
    return null;
  }
}

function pruneExpired(vault, now) {
  let changed = false;
  for (const id of Object.keys(vault)) {
    if (!vault[id] || vault[id].expires < now) {
      delete vault[id];
      changed = true;
    }
  }
  return changed;
}

function isValidReplacements(replacements) {
  return Array.isArray(replacements) &&
    replacements.length > 0 &&
    replacements.length <= MAX_REPLACEMENTS_PER_ENTRY &&
    replacements.every(r =>
      Array.isArray(r) && r.length === 2 &&
      typeof r[0] === "string" && VAULT_PLACEHOLDER_RE.test(r[0]) &&
      typeof r[1] === "string" && r[1].length > 0 && r[1].length <= MAX_SECRET_LENGTH
    );
}

function saveVaultEntry(origin, replacements) {
  return withVaultLock(async () => {
    const now = Date.now();
    const { vault = {} } = await chrome.storage.session.get("vault");
    pruneExpired(vault, now);

    vault[crypto.randomUUID()] = { origin, replacements, created: now, expires: now + VAULT_TTL_MS };

    const ids = Object.keys(vault);
    if (ids.length > MAX_VAULT_ENTRIES) {
      ids.sort((a, b) => vault[a].expires - vault[b].expires)
        .slice(0, ids.length - MAX_VAULT_ENTRIES)
        .forEach(id => delete vault[id]);
    }
    await chrome.storage.session.set({ vault });

    const { stats = { totalBlocked: 0, todayBlocked: 0, lastDate: null }, patternStats = {} } =
      await chrome.storage.local.get(["stats", "patternStats"]);
    const today = new Date().toDateString();
    if (stats.lastDate !== today) {
      stats.todayBlocked = 0;
      stats.lastDate = today;
    }
    stats.totalBlocked = (stats.totalBlocked || 0) + replacements.length;
    stats.todayBlocked = (stats.todayBlocked || 0) + replacements.length;
    for (const [placeholder] of replacements) {
      const label = VAULT_PLACEHOLDER_RE.exec(placeholder)[1];
      patternStats[label] = (patternStats[label] || 0) + 1;
    }
    await chrome.storage.local.set({ stats, patternStats });
  });
}

// Returns { values: { placeholder: original } } for live entries from the same origin.
async function resolvePlaceholders(origin, tokens) {
  const { vault = {} } = await chrome.storage.session.get("vault");
  const now = Date.now();
  const wanted = new Set(tokens.filter(t => typeof t === "string" && VAULT_PLACEHOLDER_RE.test(t)));
  const values = {};
  // Newest first, so the most recent paste wins in the (astronomically unlikely) event
  // of a placeholder collision
  const entries = Object.values(vault)
    .filter(e => e && e.origin === origin && e.expires >= now)
    .sort((a, b) => b.created - a.created);
  for (const entry of entries) {
    for (const [placeholder, original] of entry.replacements) {
      if (wanted.has(placeholder) && !(placeholder in values)) values[placeholder] = original;
    }
  }
  return { values };
}

async function cleanupVault() {
  try {
    await withVaultLock(async () => {
      const { vault = {} } = await chrome.storage.session.get("vault");
      if (pruneExpired(vault, Date.now())) {
        await chrome.storage.session.set({ vault });
      }
    });
  } catch (err) {
    // Vault cleanup failed silently — non-critical, will retry on next alarm
  }
}

// ==================== ALLOW-LIST ====================
// Set from the masked-paste toast. Values are kept only as salted hashes, so nothing on disk
// reveals what was allowed; only generic rules can be allowed or turned off this way, and
// detector.js ignores the list for every specific rule.

const MAX_ALLOWED_VALUES = 500;
const MAX_ALLOW_REQUEST = 200;

function addAllowedValues(values) {
  return withVaultLock(async () => {
    const stored = await chrome.storage.local.get(["allowedValues", "allowSalt"]);
    const salt = stored.allowSalt || Array.from(crypto.getRandomValues(new Uint8Array(16)),
      b => b.toString(16).padStart(2, "0")).join("");
    const hashes = new Set(Array.isArray(stored.allowedValues) ? stored.allowedValues : []);
    for (const value of values) hashes.add(allowedValueHash(salt, value));
    // Oldest entries go first: a Set keeps insertion order
    await chrome.storage.local.set({ allowSalt: salt, allowedValues: [...hashes].slice(-MAX_ALLOWED_VALUES) });
  });
}

function disableGenericRule(label) {
  return withVaultLock(async () => {
    const { disabledPatterns } = await chrome.storage.local.get("disabledPatterns");
    const disabled = new Set(Array.isArray(disabledPatterns) ? disabledPatterns : []);
    disabled.add(label);
    await chrome.storage.local.set({ disabledPatterns: [...disabled] });
  });
}

function isValidAllowRequest(values) {
  return Array.isArray(values) && values.length > 0 && values.length <= MAX_ALLOW_REQUEST &&
    values.every(v => typeof v === "string" && v.length > 0 && v.length <= MAX_SECRET_LENGTH);
}

// ==================== PAUSE ====================

const PAUSE_ALARM = "pauseEnd";

// Keeps the expiry alarm in line with pausedUntil, and drops a pause that ended while the
// browser was closed.
async function syncPauseState() {
  try {
    const { pausedUntil } = await chrome.storage.local.get("pausedUntil");
    if (typeof pausedUntil === "number" && pausedUntil > Date.now()) {
      chrome.alarms.create(PAUSE_ALARM, { when: pausedUntil });
    } else {
      await chrome.alarms.clear(PAUSE_ALARM);
      if (pausedUntil !== undefined) await chrome.storage.local.remove("pausedUntil");
    }
  } catch (_) {
    // Pastes check the expiry time themselves, so a missed alarm only delays the badge
  }
  updateBadge();
}

// ==================== BADGE ====================

const BADGE_COLOR = "#0ea5e9";
const BADGE_PAUSED_COLOR = "#f59e0b";
const BADGE_PAUSED_TEXT = "OFF";

async function updateBadge() {
  try {
    const { stats = {}, pausedUntil } = await chrome.storage.local.get(["stats", "pausedUntil"]);
    if (isPaused({ pausedUntil })) {
      chrome.action.setBadgeText({ text: BADGE_PAUSED_TEXT });
      chrome.action.setBadgeBackgroundColor({ color: BADGE_PAUSED_COLOR });
      return;
    }
    // todayBlocked is only reset on the next paste — don't show yesterday's count
    const count = stats.lastDate === new Date().toDateString() ? (stats.todayBlocked || 0) : 0;
    chrome.action.setBadgeText({ text: count > 0 ? String(count) : "" });
    chrome.action.setBadgeBackgroundColor({ color: BADGE_COLOR });
  } catch (err) {
    // Silent fail
  }
}

// "Pause on this site" shows on that site's tabs only. tab.url is only visible on sites we hold
// a host permission for, which every protected site is; a null text falls back to the global badge.
// A tab's colour can't fall back the same way, so it's always set.
function applyTabBadge(tab, { pausedSites, timedPause }) {
  if (!tab?.id || !tab.url) return;
  let hostname;
  try {
    hostname = new URL(tab.url).hostname;
  } catch (_) {
    return;
  }
  const paused = pausedSites.includes(hostname);
  chrome.action.setBadgeText({ tabId: tab.id, text: paused ? BADGE_PAUSED_TEXT : null });
  chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: paused || timedPause ? BADGE_PAUSED_COLOR : BADGE_COLOR });
}

async function getPauseState() {
  const { pausedSites, pausedUntil } = await chrome.storage.local.get(["pausedSites", "pausedUntil"]);
  return { pausedSites: Array.isArray(pausedSites) ? pausedSites : [], timedPause: isPaused({ pausedUntil }) };
}

async function updateAllTabBadges() {
  try {
    const [state, tabs] = await Promise.all([getPauseState(), chrome.tabs.query({})]);
    tabs.forEach(tab => applyTabBadge(tab, state));
  } catch (_) {
    // Badge only — never affects masking
  }
}

// Initialize on startup (service workers restart often, and alarms survive them)
syncPauseState();

// Listen for storage changes to re-register sites, update badge, check milestones, and track weekly stats
chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area !== "local") return;

  if (changes.removedDefaults || changes.customSites) {
    debouncedRegister();
  }

  if (changes.pausedUntil || changes.pausedSites) {
    syncPauseState();
    updateAllTabBadges();
  }

  if (changes.stats) {
    updateBadge();
    checkMilestones(changes.stats.newValue, changes.stats.oldValue);

    // Update weekly stats. Under the vault lock: two pastes landing together would otherwise
    // both read the same count and one increment would be lost.
    if (changes.stats.newValue && changes.stats.oldValue) {
      const diff = (changes.stats.newValue.totalBlocked || 0) - (changes.stats.oldValue.totalBlocked || 0);
      if (diff > 0) {
        try {
          await withVaultLock(async () => {
            const { weeklyStats = { weekStart: getWeekStart(new Date()), weekBlocked: 0 } } =
              await chrome.storage.local.get("weeklyStats");
            weeklyStats.weekBlocked = (weeklyStats.weekBlocked || 0) + diff;
            await chrome.storage.local.set({ weeklyStats });
          });
        } catch (err) {}
      }
    }
  }
});

// ==================== MILESTONES ====================

const MILESTONES = [100, 500, 1000, 5000, 10000, 50000, 100000];

async function checkMilestones(newStats, oldStats) {
  if (!newStats || !oldStats) return;

  const newTotal = newStats.totalBlocked || 0;
  const oldTotal = oldStats.totalBlocked || 0;

  for (const milestone of MILESTONES) {
    if (oldTotal < milestone && newTotal >= milestone) {
      // Milestone reached! Notify all tabs
      notifyMilestone(milestone, newTotal);
      break;
    }
  }
}

async function notifyMilestone(milestone, total) {
  try {
    // Only notify the active tab to avoid disrupting other work
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
      chrome.tabs.sendMessage(tab.id, {
        action: "milestone",
        milestone,
        total
      }).catch(() => {});
    }
  } catch (err) {
    // Milestone notification failed silently — non-critical
  }
}

// ==================== WEEKLY SUMMARY ====================

async function checkWeeklySummary() {
  try {
    const now = new Date();
    const dayOfWeek = now.getDay(); // 0 = Sunday

    // Only show on Sunday
    if (dayOfWeek !== 0) return;

    const { weeklyStats = { weekStart: null, weekBlocked: 0 }, stats = {}, weeklyReport } =
      await chrome.storage.local.get(["weeklyStats", "stats", "weeklyReport"]);

    const currentWeekStart = getWeekStart(now);

    // If it's a new week and we have data from last week
    if (weeklyStats.weekStart && weeklyStats.weekStart !== currentWeekStart && weeklyStats.weekBlocked > 0) {
      if (weeklyReport === true) {
        await showWeeklyNotification(weeklyStats.weekBlocked, stats.totalBlocked || 0);
      }

      // Reset whether or not it was shown, so opting in later doesn't report months as one week
      await chrome.storage.local.set({
        weeklyStats: { weekStart: currentWeekStart, weekBlocked: 0 }
      });
    } else if (!weeklyStats.weekStart) {
      // Initialize weekly tracking
      await chrome.storage.local.set({
        weeklyStats: { weekStart: currentWeekStart, weekBlocked: 0 }
      });
    }
  } catch (err) {
    // Weekly summary failed silently — non-critical, will retry next alarm
  }
}

function getWeekStart(date) {
  const d = new Date(date);
  const day = d.getDay();
  // Use local date arithmetic throughout — toISOString() returns UTC which
  // can differ from local date by up to a day for users west of UTC
  // new Date(y, m, d - day) rolls back across month/year boundaries correctly
  const start = new Date(d.getFullYear(), d.getMonth(), d.getDate() - day);
  const yyyy = start.getFullYear();
  const mm   = String(start.getMonth() + 1).padStart(2, '0');
  const dd   = String(start.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

async function showWeeklyNotification(weekBlocked, totalBlocked) {
  try {
    await chrome.notifications.create("weekly-summary", {
      type: "basic",
      iconUrl: "icons/icon-128.png",
      title: chrome.i18n.getMessage("weekly_title"),
      message: chrome.i18n.getMessage("weekly_message", [String(weekBlocked), totalBlocked.toLocaleString()]),
      priority: 1
    });
  } catch (err) {
    // Notification creation failed silently — non-critical
  }
}

// ==================== MESSAGE HANDLER ====================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Only accept messages from this extension (content scripts or popup)
  if (sender.id !== chrome.runtime.id) return false;

  if (request?.action === "vault:save") {
    const origin = senderOrigin(sender);
    if (!origin || !isValidReplacements(request.replacements)) {
      sendResponse({ ok: false, error: "invalid request" });
      return false;
    }
    saveVaultEntry(origin, request.replacements)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false, error: "save failed" }));
    return true;
  }

  if (request?.action === "vault:resolve") {
    const origin = senderOrigin(sender);
    if (!origin || !Array.isArray(request.tokens)) {
      sendResponse({ values: {} });
      return false;
    }
    resolvePlaceholders(origin, request.tokens.slice(0, MAX_REPLACEMENTS_PER_ENTRY))
      .then(sendResponse)
      .catch(() => sendResponse({ values: {} }));
    return true;
  }

  if (request?.action === "allow:add") {
    if (!senderOrigin(sender) || !isValidAllowRequest(request.values)) {
      sendResponse({ ok: false });
      return false;
    }
    addAllowedValues(request.values)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (request?.action === "rule:disable") {
    if (!senderOrigin(sender) || !GENERIC_LABELS.has(request.label)) {
      sendResponse({ ok: false });
      return false;
    }
    disableGenericRule(request.label)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (request?.action === "badge:sync") {
    if (!sender.tab) {
      sendResponse({ ok: false });
      return false;
    }
    getPauseState()
      .then(state => applyTabBadge(sender.tab, state))
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  sendResponse({ error: "unknown action" });
  return false;
});
