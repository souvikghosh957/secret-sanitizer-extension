// background.js - Service Worker for Secret Sanitizer
// Handles periodic cleanup, badge updates, and context menu

// Periodic vault cleanup (every 5 minutes)
chrome.alarms.create("vaultCleanup", { periodInMinutes: 5 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "vaultCleanup") {
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
});

// Update badge with blocked count
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

// Listen for storage changes to update badge
chrome.storage.onChanged.addListener((changes) => {
  if (changes.stats) {
    updateBadge();
  }
});

// Context menu for quick access (simplified - just opens popup)
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "open-sanitizer",
    title: "Open Secret Sanitizer",
    contexts: ["page", "editable"]
  });
});

chrome.contextMenus.onClicked.addListener(() => {
  chrome.action.openPopup();
});

// Handle decryption requests from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "decrypt") {
    decryptVaultData(request.data).then(decrypted => {
      sendResponse({ decrypted });
    }).catch(err => {
      console.error("Decryption error:", err);
      sendResponse({ decrypted: request.data }); // Return original on error
    });
    return true; // Async response
  }
});

// Decrypt vault data (same logic as content script)
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