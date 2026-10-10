// background.js - Service Worker for Secret Sanitizer

importScripts("sites.js");

const CONTENT_SCRIPT_FILES = ["patterns.js", "detector.js", "content_script.js"];

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
      await chrome.scripting.registerContentScripts(
        contentScriptsFor("defaults", activeDefaults.map(siteMatchPattern))
      );
    } catch (err) {
      console.warn("Content script registration failed for default sites:", err);
    }
  }

  const custom = Array.isArray(customSites) ? customSites : [];
  const validCustom = [...new Set(custom.map(normalizeSite).filter(Boolean))]
    .filter(s => !DEFAULT_SITES.includes(s));
  for (const [i, site] of validCustom.entries()) {
    try {
      await chrome.scripting.registerContentScripts(contentScriptsFor(`custom-${i}`, [siteMatchPattern(site)]));
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

chrome.runtime.onInstalled.addListener(() => {
  registerContentScripts();
  ensureAlarms();
});
chrome.runtime.onStartup.addListener(() => {
  registerContentScripts();
  ensureAlarms();
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "vaultCleanup") {
    await cleanupVault();
    updateBadge(); // clears yesterday's count shortly after midnight
  } else if (alarm.name === "weeklySummary") {
    await checkWeeklySummary();
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

// ==================== BADGE ====================

async function updateBadge() {
  try {
    const { stats = {} } = await chrome.storage.local.get("stats");
    // todayBlocked is only reset on the next paste — don't show yesterday's count
    const count = stats.lastDate === new Date().toDateString() ? (stats.todayBlocked || 0) : 0;
    chrome.action.setBadgeText({ text: count > 0 ? String(count) : "" });
    chrome.action.setBadgeBackgroundColor({ color: "#0ea5e9" });
  } catch (err) {
    // Silent fail
  }
}

// Initialize badge on startup
updateBadge();

// Listen for storage changes to re-register sites, update badge, check milestones, and track weekly stats
chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area !== "local") return;

  if (changes.removedDefaults || changes.customSites) {
    debouncedRegister();
  }

  if (changes.stats) {
    updateBadge();
    checkMilestones(changes.stats.newValue, changes.stats.oldValue);

    // Update weekly stats
    if (changes.stats.newValue && changes.stats.oldValue) {
      const diff = (changes.stats.newValue.totalBlocked || 0) - (changes.stats.oldValue.totalBlocked || 0);
      if (diff > 0) {
        try {
          const { weeklyStats = { weekStart: getWeekStart(new Date()), weekBlocked: 0 } } =
            await chrome.storage.local.get("weeklyStats");
          weeklyStats.weekBlocked = (weeklyStats.weekBlocked || 0) + diff;
          await chrome.storage.local.set({ weeklyStats });
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

    const { weeklyStats = { weekStart: null, weekBlocked: 0 }, stats = {} } =
      await chrome.storage.local.get(["weeklyStats", "stats"]);

    const currentWeekStart = getWeekStart(now);

    // If it's a new week and we have data from last week
    if (weeklyStats.weekStart && weeklyStats.weekStart !== currentWeekStart && weeklyStats.weekBlocked > 0) {
      // Show notification
      await showWeeklyNotification(weeklyStats.weekBlocked, stats.totalBlocked || 0);

      // Reset weekly stats
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
      title: "Weekly Protection Report",
      message: `This week you protected ${weekBlocked} secrets!\nAll Time Protection: ${totalBlocked.toLocaleString()}`,
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

  sendResponse({ error: "unknown action" });
  return false;
});
