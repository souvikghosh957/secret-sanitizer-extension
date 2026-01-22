// popup.js - Enhanced Secret Sanitizer Popup
// - Dark mode support
// - Test/preview mode
// - Export/import settings
// - Better UX

// Notification helper
function showNotification(message, type = "success") {
  const notification = document.createElement("div");
  notification.className = `notification notification-${type}`;
  notification.textContent = message;
  document.body.appendChild(notification);
  
  setTimeout(() => notification.classList.add("show"), 10);
  setTimeout(() => {
    notification.classList.remove("show");
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

// Decrypt vault data (simplified - actual decryption in content script)
async function decryptData(encryptedData) {
  try {
    // Send to background script for decryption (has access to crypto API)
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { action: "decrypt", data: encryptedData },
        (response) => {
          resolve(response?.decrypted || encryptedData);
        }
      );
    });
  } catch (_) {
    // Fallback: try simple base64 decode
    try {
      if (typeof encryptedData === 'string' && !encryptedData.startsWith('[')) {
        const decoded = decodeURIComponent(escape(atob(encryptedData)));
        return JSON.parse(decoded);
      }
    } catch (_) {}
    return encryptedData;
  }
}

// Test sanitization (enhanced with more patterns)
function testSanitize(text) {
  // Comprehensive test patterns matching content script
  const patterns = [
    [/\bAKIA[0-9A-Z]{16}\b/gi, "AWS_KEY"],
    [/\b[A-Za-z0-9/+=]{40}\b/g, "AWS_SECRET_KEY"],
    [/\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g, "GITHUB_TOKEN"],
    [/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "JWT"],
    [/\b[A-Z]{5}\d{4}[A-Z]{1}\b/g, "PAN"],
    [/\b[6-9]\d{9}\b/g, "INDIAN_PHONE"],
    [/\bopenai_[A-Za-z0-9]{48,}\b/gi, "OPENAI_KEY"],
    [/\bsk_test_[A-Za-z0-9]{24,}\b/gi, "STRIPE_TEST_KEY"],
    [/\bpk_test_[A-Za-z0-9]{24,}\b/gi, "STRIPE_TEST_PUB_KEY"],
    [/\brzp_test_[A-Za-z0-9]{14,}\b/gi, "RAZORPAY_TEST_KEY"],
    [/\bAC[a-z0-9]{32}\b/gi, "TWILIO_SID"],
    [/\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}\b/g, "FIREBASE_KEY"],
    [/\b(?:success|failure|test)@(?:upi|razorpay|payu)\b/gi, "UPI_TEST_ID"],
    [/(?:otp|pin|code)[\s:=]+['"]?(\d{4,8})['"]?/gi, "OTP_CODE"],
    [/-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|EC\s+PRIVATE)\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?(?:PRIVATE|EC\s+PRIVATE)\s+KEY-----/gi, "PRIVATE_KEY"],
    [/(?:api[_-]?key|apikey|api_key)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?/gi, "API_KEY_FORMAT"],
    [/['"][A-Za-z0-9]{20,}['"]/g, "QUOTED_SECRET"],
    [/\b[A-Za-z0-9]{40,}\b/g, "LONG_RANDOM_STRING"],
    [/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, "BASE64_SECRET"],
  ];
  
  let masked = text;
  let count = 0;
  
  for (const [pattern, label] of patterns) {
    const matches = masked.match(pattern);
    if (matches) {
      count += matches.length;
      masked = masked.replace(pattern, `[${label}]`);
    }
  }
  
  return { maskedText: masked, count };
}

document.addEventListener("DOMContentLoaded", async () => {
  console.log("🛡️ Secret Sanitizer popup opened");

  try {
    const { vault = {}, stats = { totalBlocked: 0, todayBlocked: 0 }, disabledPatterns = [], customSites = [], darkMode = null, autoDarkMode = true, useEncryption = true } = await chrome.storage.local.get(["vault", "stats", "disabledPatterns", "customSites", "darkMode", "autoDarkMode", "useEncryption"]);
    const disabled = new Set(disabledPatterns);
    
    // Apply dark mode (auto-detect or manual)
    const shouldUseDarkMode = autoDarkMode && darkMode === null
      ? window.matchMedia('(prefers-color-scheme: dark)').matches
      : darkMode === true;
    
    if (shouldUseDarkMode) {
      document.body.classList.add("dark-mode");
    }
    
    // Listen for system preference changes
    if (autoDarkMode) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (darkMode === null) { // Only if not manually set
          document.body.classList.toggle("dark-mode", e.matches);
        }
      });
    }

    const now = Date.now();

    // Clean expired vault
    let cleaned = false;
    Object.keys(vault).forEach(key => {
      if (vault[key] && vault[key].expires < now) {
        delete vault[key];
        cleaned = true;
      }
    });
    if (cleaned) await chrome.storage.local.set({ vault });

    // Stats
    document.getElementById("total").textContent = stats.totalBlocked || 0;
    document.getElementById("today").textContent = stats.todayBlocked || 0;

    // Recent with search
    const recentList = document.getElementById("recentList");
    const vaultSearch = document.getElementById("vaultSearch");
    let vaultSearchTerm = "";
    
    const renderRecent = (searchTerm = "") => {
      if (!recentList) return;
      recentList.innerHTML = "";
      
      let traceIds = Object.keys(vault)
        .filter(id => {
          if (!searchTerm) return true;
          const entry = vault[id];
          if (!entry) return false;
          return id.toLowerCase().includes(searchTerm.toLowerCase());
        })
        .sort((a, b) => (vault[b]?.expires || 0) - (vault[a]?.expires || 0))
        .slice(0, 20);

      if (traceIds.length === 0) {
        recentList.innerHTML = `<li class="empty-state">${searchTerm ? 'No matches found' : 'No recent sanitizations'}</li>`;
      } else {
        traceIds.forEach(id => {
          const entry = vault[id];
          if (!entry) return;
          const minsLeft = Math.max(1, Math.round((entry.expires - now) / 60000));
          const count = entry.encrypted 
            ? (typeof entry.replacements === 'string' ? '?' : entry.replacements?.length || 0)
            : (Array.isArray(entry.replacements) ? entry.replacements.length : 0);
          const li = document.createElement("li");
          li.className = "vault-item";
          li.innerHTML = `
            <div class="vault-item-content">
              <strong>${id.slice(0, 8)}...</strong>
              <span class="vault-badge">${count}</span>
            </div>
            <small>${minsLeft} min left</small>
          `;
          recentList.appendChild(li);
        });
      }
    };
    
    renderRecent();
    
    // Debounced search
    let searchTimeout;
    if (vaultSearch) {
      vaultSearch.addEventListener("input", (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
          vaultSearchTerm = e.target.value;
          renderRecent(vaultSearchTerm);
        }, 200);
      });
    }

    // Unmask with decryption support and loading state
    const unmaskBtn = document.getElementById("unmaskBtn");
    if (unmaskBtn) {
      unmaskBtn.addEventListener("click", async () => {
        const text = document.getElementById("inputText").value.trim();
        if (!text) {
          showNotification("Paste response first!", "warning");
          return;
        }

        // Show loading
        unmaskBtn.classList.add("loading");
        const output = document.getElementById("output");

        let unmasked = text;
        let replacedCount = 0;

      for (const entry of Object.values(vault)) {
        if (!entry || entry.expires < now) continue;
        
        let replacements = entry.replacements;
        // Decrypt if needed
        if (entry.encrypted) {
          try {
            replacements = await decryptData({ encrypted: true, data: replacements });
          } catch (err) {
            console.error("Decryption error:", err);
            continue;
          }
        } else if (typeof replacements === 'string' && !replacements.startsWith('[')) {
          // Old format - try to decrypt
          try {
            replacements = await decryptData({ encrypted: false, data: replacements });
          } catch (err) {
            // If it fails, might be already decrypted
          }
        }
        
        for (const [placeholder, original] of replacements) {
          const escaped = placeholder.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const regex = new RegExp(escaped, "g");
          if (regex.test(unmasked)) {
            unmasked = unmasked.replace(regex, original);
            replacedCount++;
          }
        }
      }

        if (replacedCount > 0) {
          output.textContent = unmasked;
          output.classList.remove("hidden");
          showNotification(`Unmasked ${replacedCount} secret${replacedCount > 1 ? 's' : ''}`, "success");
        } else {
          output.textContent = "No placeholders found in vault.";
          output.classList.remove("hidden");
          showNotification("No matching placeholders found", "warning");
        }
        
        unmaskBtn.classList.remove("loading");
      });
    }
    
    // Test/Preview mode with loading state
    const testBtn = document.getElementById("testBtn");
    if (testBtn) {
      testBtn.addEventListener("click", () => {
        const testText = document.getElementById("testInput")?.value.trim();
        if (!testText) {
          showNotification("Enter text to test", "warning");
          return;
        }
        
        // Show loading
        testBtn.classList.add("loading");
        const testOutput = document.getElementById("testOutput");
        
        // Use requestAnimationFrame for smooth UI
        requestAnimationFrame(() => {
          const result = testSanitize(testText);
          if (testOutput) {
            testOutput.textContent = result.maskedText;
            testOutput.classList.remove("hidden");
            if (result.count > 0) {
              showNotification(`Found ${result.count} potential secret${result.count > 1 ? 's' : ''}`, "success");
            } else {
              showNotification("No secrets detected", "warning");
            }
          }
          testBtn.classList.remove("loading");
        });
      });
    }
    
    // Dark mode toggle
    const darkModeToggle = document.getElementById("darkModeToggle");
    if (darkModeToggle) {
      darkModeToggle.addEventListener("click", async () => {
        const currentMode = document.body.classList.contains("dark-mode");
        const newMode = !currentMode;
        await chrome.storage.local.set({ darkMode: newMode });
        document.body.classList.toggle("dark-mode", newMode);
        darkModeToggle.querySelector("i").className = newMode ? "fas fa-sun" : "fas fa-moon";
      });
      if (shouldUseDarkMode) {
        darkModeToggle.querySelector("i").className = "fas fa-sun";
      }
    }
    
    // Auto dark mode toggle
    const autoDarkModeCheckbox = document.getElementById("autoDarkMode");
    if (autoDarkModeCheckbox) {
      autoDarkModeCheckbox.checked = autoDarkMode;
      autoDarkModeCheckbox.addEventListener("change", async (e) => {
        await chrome.storage.local.set({ autoDarkMode: e.target.checked });
        if (e.target.checked) {
          // Apply system preference
          const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
          document.body.classList.toggle("dark-mode", systemDark);
          await chrome.storage.local.set({ darkMode: null }); // Reset to auto
        }
        showNotification("Auto dark mode " + (e.target.checked ? "enabled" : "disabled"), "success");
      });
    }
    
    // Encryption toggle
    const encryptionCheckbox = document.getElementById("useEncryption");
    if (encryptionCheckbox) {
      encryptionCheckbox.checked = useEncryption;
      encryptionCheckbox.addEventListener("change", async (e) => {
        await chrome.storage.local.set({ useEncryption: e.target.checked });
        showNotification("Encryption setting saved", "success");
      });
    }
    
    // Delete secrets
    const clearVaultBtn = document.getElementById("clearVault");
    if (clearVaultBtn) {
      clearVaultBtn.addEventListener("click", async () => {
        if (confirm("Delete all stored secrets? This cannot be undone.")) {
          await chrome.storage.local.set({ vault: {} });
          showNotification("Secrets deleted", "success");
          // Reload recent list
          setTimeout(() => location.reload(), 500);
        }
      });
    }
    
    // Export settings
    const exportBtn = document.getElementById("exportSettings");
    if (exportBtn) {
      exportBtn.addEventListener("click", async () => {
        const data = await chrome.storage.local.get(["disabledPatterns", "customSites", "useEncryption"]);
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `secret-sanitizer-settings-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showNotification("Settings exported", "success");
      });
    }
    
    // Import settings
    const importBtn = document.getElementById("importSettings");
    const importFile = document.getElementById("importFile");
    if (importBtn && importFile) {
      importBtn.addEventListener("click", () => importFile.click());
      importFile.addEventListener("change", async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        try {
          const text = await file.text();
          const data = JSON.parse(text);
          await chrome.storage.local.set(data);
          showNotification("Settings imported! Please refresh.", "success");
          setTimeout(() => location.reload(), 1500);
        } catch (err) {
          showNotification("Invalid settings file", "error");
        }
      });
    }

    // Tab switching
    document.querySelectorAll(".tab-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
        document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
        btn.classList.add("active");
        document.getElementById(`${btn.dataset.tab}-tab`).classList.add("active");
      });
    });

    // Pattern statistics
    const patternStatsDiv = document.getElementById("patternStats");
    if (patternStatsDiv) {
      (async () => {
        const { patternStats = {} } = await chrome.storage.local.get("patternStats");
        const statsList = Object.entries(patternStats)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10);
        
        if (statsList.length === 0) {
          patternStatsDiv.innerHTML = '<p class="empty-state">No statistics yet. Patterns will be tracked as you use the extension.</p>';
        } else {
          patternStatsDiv.innerHTML = statsList.map(([pattern, count]) => `
            <div class="stat-item">
              <span class="stat-label">${pattern}</span>
              <span class="stat-value">${count}</span>
            </div>
          `).join('');
        }
      })();
    }
    
    // Patterns (all ENABLED by default) - comprehensive list
    const allLabels = [
      "AWS_KEY","AWS_TEMP_KEY","AWS_SECRET_KEY",
      "GITHUB_TOKEN","JWT","DB_CONN","CREDIT_CARD",
      "AADHAAR","PAN","INDIAN_PHONE","GSTIN","IFSC",
      "UPI_ID","UPI_ID_GENERIC","UPI_TEST_ID","PAYMENT_UPI_ID",
      "DRIVING_LICENSE","VOTER_ID","BANK_ACCOUNT","EMAIL_IN_SECRET",
      "STRIPE_KEY","STRIPE_TEST_KEY","STRIPE_PUB_KEY","STRIPE_TEST_PUB_KEY",
      "TWILIO_SID","TWILIO_AUTH_TOKEN","FIREBASE_KEY",
      "RAZORPAY_KEY","RAZORPAY_TEST_KEY","RAZORPAY_TEST_SECRET",
      "PAYTM_KEY","PAYTM_MERCHANT",
      "PASSWORD_HINT","OTP_CODE","PASSPORT","VEHICLE_REG",
      "OPENAI_KEY","GROK_KEY","GOOGLE_API_KEY","BEARER_TOKEN","NPM_TOKEN",
      "GENERIC_SECRET_KEY","LONG_RANDOM_STRING","BASE64_SECRET",
      "API_KEY_FORMAT","SECRET_KEY_FORMAT","ACCESS_KEY_FORMAT",
      "QUOTED_SECRET","PRIVATE_KEY","PGP_PRIVATE_KEY"
    ];
    const togglesDiv = document.getElementById("patternToggles");

    if (togglesDiv) {
      const renderPatterns = (search = "") => {
        togglesDiv.innerHTML = "";
        allLabels
          .filter(l => l.toLowerCase().includes(search.toLowerCase()))
          .forEach(label => {
            const div = document.createElement("div");
            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.checked = !disabled.has(label);
            checkbox.id = `toggle-${label}`;

            const lbl = document.createElement("label");
            lbl.htmlFor = checkbox.id;
            lbl.textContent = label;

            div.appendChild(checkbox);
            div.appendChild(lbl);
            togglesDiv.appendChild(div);
          });
      };

      renderPatterns();
      // Debounced pattern search
      let patternSearchTimeout;
      const patternSearch = document.getElementById("patternSearch");
      if (patternSearch) {
        patternSearch.addEventListener("input", e => {
          clearTimeout(patternSearchTimeout);
          patternSearchTimeout = setTimeout(() => {
            renderPatterns(e.target.value);
          }, 150);
        });
      }
    }
    
    // Keyboard shortcuts
    document.addEventListener("keydown", (e) => {
      if (e.ctrlKey || e.metaKey) {
        switch(e.key.toLowerCase()) {
          case 't':
            e.preventDefault();
            document.getElementById("testBtn")?.click();
            break;
          case 'u':
            e.preventDefault();
            document.getElementById("unmaskBtn")?.click();
            break;
          case 'd':
            e.preventDefault();
            if (confirm("Delete all stored secrets?")) {
              document.getElementById("clearVault")?.click();
            }
            break;
        }
      }
    });
    
    // Quick action buttons
    document.getElementById("quickTest")?.addEventListener("click", () => {
      document.getElementById("testBtn")?.click();
    });
    document.getElementById("quickUnmask")?.addEventListener("click", () => {
      document.getElementById("unmaskBtn")?.click();
    });
    document.getElementById("quickClear")?.addEventListener("click", () => {
      if (confirm("Delete all stored secrets?")) {
        document.getElementById("clearVault")?.click();
      }
    });

    // Custom sites - robust parsing
    const siteList = document.getElementById("siteList");
    const renderSites = () => {
      if (siteList) siteList.innerHTML = "";
      customSites.forEach(site => {
        const li = document.createElement("li");
        li.textContent = site;
        const remove = document.createElement("button");
        remove.textContent = "Remove";
        remove.onclick = () => {
          customSites.splice(customSites.indexOf(site), 1);
          renderSites();
        };
        li.appendChild(remove);
        if (siteList) siteList.appendChild(li);
      });
    };
    renderSites();

    const addSiteBtn = document.getElementById("addSite");
    if (addSiteBtn) {
      addSiteBtn.addEventListener("click", () => {
        const input = document.getElementById("newSite");
        if (!input) return;

        let urlStr = input.value.trim();
        if (!urlStr) return;

        try {
          const url = new URL(urlStr.startsWith("http") ? urlStr : "https://" + urlStr);
          const host = url.host;

          if (host && !customSites.includes(host)) {
            customSites.push(host);
            input.value = "";
            renderSites();
          } else if (customSites.includes(host)) {
            alert("Domain already added");
          }
        } catch (_) {
          alert("Invalid URL - try grok.com or https://grok.com");
        }
      });
    }

    // Save all settings - with explicit permission request + cleaner alerts
    const saveSettingsBtn = document.getElementById("saveSettings");
    if (saveSettingsBtn) {
      saveSettingsBtn.addEventListener("click", async () => {
        const newDisabled = allLabels.filter(label => {
          const cb = document.getElementById(`toggle-${label}`);
          return cb && !cb.checked;
        });

        await chrome.storage.local.set({ disabledPatterns: newDisabled, customSites });

        try {
          // Request permission for custom sites
          if (customSites.length > 0) {
            const origins = customSites.map(s => `*://${s}/*`);
            const granted = await chrome.permissions.request({ origins });
            if (!granted) {
              alert("Permission denied for custom sites.\nSanitizing won't work on them until granted.");
            }
          }

          // Unregister and re-register
          await chrome.scripting.unregisterContentScripts();

          const defaultMatches = [
            "*://chatgpt.com/*",
            "*://chat.openai.com/*",
            "*://claude.ai/*",
            "*://grok.x.ai/*",
            "*://grok.com/*",
            "*://gemini.google.com/*",
            "*://www.perplexity.ai/*"
          ];

          const allMatches = [...defaultMatches, ...customSites.map(s => `*://${s}/*`)];

          await chrome.scripting.registerContentScripts([{
            id: "secret-sanitizer",
            matches: allMatches,
            js: ["content_script.js"],
            runAt: "document_idle"
          }]);

          showNotification("Settings saved! Refresh pages to apply.", "success");
        } catch (err) {
          showNotification("Patterns saved. Sites update failed: " + err.message, "error");
        }
      });
    }
  } catch (err) {
    console.error("🛡️ Popup error:", err);
  }
});