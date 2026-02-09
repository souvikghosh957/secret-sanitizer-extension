// background.js - Service Worker for Secret Sanitizer
// Handles periodic cleanup, badge updates, context menu, weekly summary, and milestones

// ==================== ALARMS ====================

// Periodic vault cleanup (every 5 minutes)
chrome.alarms.create("vaultCleanup", { periodInMinutes: 5 });

// Weekly summary (check daily, show on Sundays)
chrome.alarms.create("weeklySummary", { periodInMinutes: 1440 }); // Daily check

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "vaultCleanup") {
    await cleanupVault();
  } else if (alarm.name === "weeklySummary") {
    await checkWeeklySummary();
  }
});

// ==================== VAULT CLEANUP ====================

async function cleanupVault() {
  try {
    const { vault = {} } = await chrome.storage.local.get("vault");
    const now = Date.now();
    let cleaned = false;

    Object.keys(vault).forEach(key => {
      if (vault[key] && vault[key].expires < now) {
        delete vault[key];
        cleaned = true;
      }
    });

    if (cleaned) {
      await chrome.storage.local.set({ vault });
      updateBadge();
    }
  } catch (err) {
    console.error("Vault cleanup error:", err);
  }
}

// ==================== BADGE ====================

async function updateBadge() {
  try {
    const { stats = { todayBlocked: 0 } } = await chrome.storage.local.get("stats");
    const count = stats.todayBlocked || 0;
    chrome.action.setBadgeText({ text: count > 0 ? String(count) : "" });
    chrome.action.setBadgeBackgroundColor({ color: "#0ea5e9" });
  } catch (err) {
    // Silent fail
  }
}

// Initialize badge on startup
updateBadge();

// Listen for storage changes to update badge and check milestones
chrome.storage.onChanged.addListener((changes) => {
  if (changes.stats) {
    updateBadge();
    checkMilestones(changes.stats.newValue, changes.stats.oldValue);
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
    // Send message to all active tabs to show celebration
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      if (tab.id) {
        chrome.tabs.sendMessage(tab.id, {
          action: "milestone",
          milestone,
          total
        }).catch(() => {}); // Ignore errors for tabs without content script
      }
    }
  } catch (err) {
    console.error("Milestone notification error:", err);
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
    console.error("Weekly summary error:", err);
  }
}

function getWeekStart(date) {
  const d = new Date(date);
  const day = d.getDay();
  const diff = d.getDate() - day;
  d.setDate(diff);
  d.setHours(0, 0, 0, 0);
  return d.toISOString().split('T')[0];
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
    console.error("Notification error:", err);
  }
}

// Update weekly stats when secrets are blocked
chrome.storage.onChanged.addListener(async (changes) => {
  if (changes.stats && changes.stats.newValue && changes.stats.oldValue) {
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
});

// ==================== MESSAGE HANDLER ====================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "decrypt") {
    decryptVaultData(request.data).then(decrypted => {
      sendResponse({ decrypted });
    }).catch(err => {
      console.error("Decryption error:", err);
      sendResponse({ decrypted: request.data });
    });
    return true;
  }
});

// ==================== DECRYPTION ====================

async function decryptVaultData(encryptedData) {
  try {
    const { useEncryption = true } = await chrome.storage.local.get("useEncryption");
    if (!useEncryption) {
      if (typeof encryptedData === 'string' && encryptedData.startsWith('[')) {
        return encryptedData;
      }
      if (typeof encryptedData === 'object' && encryptedData.encrypted === false) {
        const decoded = decodeURIComponent(escape(atob(encryptedData.data)));
        return JSON.parse(decoded);
      }
      return encryptedData;
    }

    if (typeof encryptedData === 'object' && encryptedData.encrypted === true) {
      const extensionId = chrome.runtime.id;
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(extensionId + "secret-sanitizer-vault-key"),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
      );

      const key = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: new TextEncoder().encode(extensionId),
          iterations: 100000,
          hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );

      const combined = Uint8Array.from(atob(encryptedData.data), c => c.charCodeAt(0));
      const iv = combined.slice(0, 12);
      const encrypted = combined.slice(12);

      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encrypted
      );

      const json = new TextDecoder().decode(decrypted);
      return JSON.parse(json);
    }

    // Fallback for old format
    if (typeof encryptedData === 'string' && !encryptedData.startsWith('[')) {
      const decoded = decodeURIComponent(escape(atob(encryptedData)));
      return JSON.parse(decoded);
    }

    return encryptedData;
  } catch (err) {
    console.error("Decryption error:", err);
    return encryptedData;
  }
}
