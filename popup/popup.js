// popup.js - Premium Secret Sanitizer Redesign
// - Hero stats with count-up animation
// - Unified smart action area (test vs unmask auto-detection)
// - Accordion settings with auto-save
// - Simplified recent section

// ==================== UTILITIES ====================

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

// Animated count-up for hero stats
function animateCount(element, target, duration = 1000) {
  const start = 0;
  const startTime = performance.now();

  element.classList.add('animate');

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);

    // Ease-out cubic
    const easeOut = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(start + (target - start) * easeOut);

    element.textContent = current.toLocaleString();

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

// Decrypt vault data
async function decryptData(encryptedData) {
  try {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { action: "decrypt", data: encryptedData },
        (response) => {
          resolve(response?.decrypted || encryptedData);
        }
      );
    });
  } catch (_) {
    try {
      if (typeof encryptedData === 'string' && !encryptedData.startsWith('[')) {
        const decoded = decodeURIComponent(escape(atob(encryptedData)));
        return JSON.parse(decoded);
      }
    } catch (_) {}
    return encryptedData;
  }
}

// Test sanitization patterns
function testSanitize(text) {
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

// Detect if text contains placeholders (unmask mode)
function detectMode(text) {
  // Look for [PLACEHOLDER] patterns from our sanitizer
  const placeholderPattern = /\[(AWS_KEY|GITHUB_TOKEN|JWT|PAN|INDIAN_PHONE|OPENAI_KEY|STRIPE_TEST_KEY|PRIVATE_KEY|API_KEY_FORMAT|PLACEHOLDER_\d+|[A-Z_]+_\d+)\]/;
  return placeholderPattern.test(text) ? 'unmask' : 'test';
}

// ==================== MAIN ====================

document.addEventListener("DOMContentLoaded", async () => {
  console.log("Secret Sanitizer popup opened");

  try {
    const {
      vault = {},
      stats = { totalBlocked: 0, todayBlocked: 0 },
      disabledPatterns = [],
      customSites = [],
      darkMode = null,
      autoDarkMode = true,
      useEncryption = true
    } = await chrome.storage.local.get([
      "vault", "stats", "disabledPatterns", "customSites",
      "darkMode", "autoDarkMode", "useEncryption"
    ]);

    const disabled = new Set(disabledPatterns);
    const now = Date.now();

    // ==================== DARK MODE ====================

    const shouldUseDarkMode = autoDarkMode && darkMode === null
      ? window.matchMedia('(prefers-color-scheme: dark)').matches
      : darkMode === true;

    if (shouldUseDarkMode) {
      document.body.classList.add("dark-mode");
    }

    if (autoDarkMode) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (darkMode === null) {
          document.body.classList.toggle("dark-mode", e.matches);
        }
      });
    }

    // ==================== CLEAN EXPIRED VAULT ====================

    let cleaned = false;
    Object.keys(vault).forEach(key => {
      if (vault[key] && vault[key].expires < now) {
        delete vault[key];
        cleaned = true;
      }
    });
    if (cleaned) await chrome.storage.local.set({ vault });

    // ==================== HERO STATS ====================

    const heroTotal = document.getElementById("heroTotal");
    const heroToday = document.getElementById("heroToday");

    if (heroTotal) {
      animateCount(heroTotal, stats.totalBlocked || 0, 800);
    }
    if (heroToday) {
      heroToday.textContent = stats.todayBlocked || 0;
    }

    // ==================== UNIFIED ACTION AREA ====================

    const actionInput = document.getElementById("actionInput");
    const actionBtn = document.getElementById("actionBtn");
    const actionIcon = document.getElementById("actionIcon");
    const actionBtnText = document.getElementById("actionBtnText");
    const actionOutput = document.getElementById("actionOutput");
    const modeIndicator = document.getElementById("modeIndicator");

    let currentMode = 'auto';

    // Update UI based on detected mode
    function updateModeUI(mode) {
      const badge = modeIndicator.querySelector('.mode-badge');

      if (mode === 'unmask') {
        actionBtn.classList.add('mode-unmask');
        actionIcon.className = 'fas fa-unlock';
        actionBtnText.textContent = 'Unmask Secrets';
        badge.className = 'mode-badge mode-unmask';
        badge.innerHTML = '<i class="fas fa-unlock"></i> Unmask mode';
      } else if (mode === 'test') {
        actionBtn.classList.remove('mode-unmask');
        actionIcon.className = 'fas fa-vial';
        actionBtnText.textContent = 'Test Masking';
        badge.className = 'mode-badge mode-test';
        badge.innerHTML = '<i class="fas fa-flask"></i> Test mode';
      } else {
        actionBtn.classList.remove('mode-unmask');
        actionIcon.className = 'fas fa-vial';
        actionBtnText.textContent = 'Analyze';
        badge.className = 'mode-badge mode-auto';
        badge.innerHTML = '<i class="fas fa-robot"></i> Auto-detect';
      }
      currentMode = mode;
    }

    // Auto-detect mode on input
    if (actionInput) {
      actionInput.addEventListener('input', (e) => {
        const text = e.target.value.trim();
        if (!text) {
          updateModeUI('auto');
        } else {
          updateModeUI(detectMode(text));
        }
      });
    }

    // Handle action button click
    if (actionBtn) {
      actionBtn.addEventListener('click', async () => {
        const text = actionInput?.value.trim();
        if (!text) {
          showNotification("Paste some text first", "warning");
          return;
        }

        actionBtn.classList.add('loading');
        const mode = detectMode(text);

        if (mode === 'unmask') {
          // Unmask mode
          let unmasked = text;
          let replacedCount = 0;

          for (const entry of Object.values(vault)) {
            if (!entry || entry.expires < now) continue;

            let replacements = entry.replacements;
            if (entry.encrypted) {
              try {
                replacements = await decryptData({ encrypted: true, data: replacements });
              } catch (err) {
                console.error("Decryption error:", err);
                continue;
              }
            } else if (typeof replacements === 'string' && !replacements.startsWith('[')) {
              try {
                replacements = await decryptData({ encrypted: false, data: replacements });
              } catch (err) {}
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

          actionOutput.textContent = unmasked;
          actionOutput.classList.remove('hidden');

          if (replacedCount > 0) {
            showNotification(`Unmasked ${replacedCount} secret${replacedCount > 1 ? 's' : ''}`, "success");
          } else {
            showNotification("No matching placeholders in vault", "warning");
          }
        } else {
          // Test mode
          requestAnimationFrame(() => {
            const result = testSanitize(text);
            actionOutput.textContent = result.maskedText;
            actionOutput.classList.remove('hidden');

            if (result.count > 0) {
              showNotification(`Found ${result.count} potential secret${result.count > 1 ? 's' : ''}`, "success");
            } else {
              showNotification("No secrets detected", "warning");
            }
          });
        }

        actionBtn.classList.remove('loading');
      });
    }

    // ==================== RECENT SECTION ====================

    const recentList = document.getElementById("recentList");
    const recentListExpanded = document.getElementById("recentListExpanded");
    const recentExpanded = document.getElementById("recentExpanded");
    const toggleExpandBtn = document.getElementById("toggleRecentExpand");
    const vaultSearch = document.getElementById("vaultSearch");

    const renderRecent = (targetList, limit = 3, searchTerm = "") => {
      if (!targetList) return;
      targetList.innerHTML = "";

      let traceIds = Object.keys(vault)
        .filter(id => {
          if (!searchTerm) return true;
          return id.toLowerCase().includes(searchTerm.toLowerCase());
        })
        .sort((a, b) => (vault[b]?.expires || 0) - (vault[a]?.expires || 0))
        .slice(0, limit);

      if (traceIds.length === 0) {
        targetList.innerHTML = `<li class="empty-state">${searchTerm ? 'No matches' : 'No recent sanitizations'}</li>`;
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
              <div>
                <span class="vault-badge">${count}</span>
                <small style="margin-left: 8px;">${minsLeft}m</small>
              </div>
            </div>
          `;
          targetList.appendChild(li);
        });
      }
    };

    // Render initial 3 items
    renderRecent(recentList, 3);

    // Expand/collapse recent
    if (toggleExpandBtn) {
      toggleExpandBtn.addEventListener('click', () => {
        const isExpanded = !recentExpanded.classList.contains('hidden');
        recentExpanded.classList.toggle('hidden');
        toggleExpandBtn.classList.toggle('expanded');

        if (!isExpanded) {
          renderRecent(recentListExpanded, 20);
        }
      });
    }

    // Search in expanded view
    let searchTimeout;
    if (vaultSearch) {
      vaultSearch.addEventListener("input", (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
          renderRecent(recentListExpanded, 20, e.target.value);
        }, 200);
      });
    }

    // ==================== DARK MODE TOGGLE ====================

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

    // ==================== TAB SWITCHING ====================

    document.querySelectorAll(".tab-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
        document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
        btn.classList.add("active");
        document.getElementById(`${btn.dataset.tab}-tab`).classList.add("active");
      });
    });

    // ==================== ACCORDION BEHAVIOR ====================

    document.querySelectorAll('.accordion-header').forEach(header => {
      header.addEventListener('click', () => {
        const accordion = header.closest('.accordion');
        accordion.classList.toggle('collapsed');
      });
    });

    // ==================== SETTINGS WITH AUTO-SAVE ====================

    // Encryption toggle (auto-save)
    const encryptionCheckbox = document.getElementById("useEncryption");
    if (encryptionCheckbox) {
      encryptionCheckbox.checked = useEncryption;
      encryptionCheckbox.addEventListener("change", async (e) => {
        await chrome.storage.local.set({ useEncryption: e.target.checked });
        showNotification("Encryption " + (e.target.checked ? "enabled" : "disabled"), "success");
      });
    }

    // Auto dark mode toggle (auto-save)
    const autoDarkModeCheckbox = document.getElementById("autoDarkMode");
    if (autoDarkModeCheckbox) {
      autoDarkModeCheckbox.checked = autoDarkMode;
      autoDarkModeCheckbox.addEventListener("change", async (e) => {
        await chrome.storage.local.set({ autoDarkMode: e.target.checked });
        if (e.target.checked) {
          const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
          document.body.classList.toggle("dark-mode", systemDark);
          await chrome.storage.local.set({ darkMode: null });
        }
        showNotification("Auto dark mode " + (e.target.checked ? "enabled" : "disabled"), "success");
      });
    }

    // Delete secrets
    const clearVaultBtn = document.getElementById("clearVault");
    if (clearVaultBtn) {
      clearVaultBtn.addEventListener("click", async () => {
        if (confirm("Delete all stored secrets? This cannot be undone.")) {
          await chrome.storage.local.set({ vault: {} });
          showNotification("All secrets deleted", "success");
          setTimeout(() => location.reload(), 500);
        }
      });
    }

    // ==================== PATTERN TOGGLES (AUTO-SAVE) ====================

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

    // Auto-save pattern toggle
    const savePatternState = async () => {
      const newDisabled = allLabels.filter(label => {
        const cb = document.getElementById(`toggle-${label}`);
        return cb && !cb.checked;
      });
      await chrome.storage.local.set({ disabledPatterns: newDisabled });
    };

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

            // Auto-save on change
            checkbox.addEventListener('change', async () => {
              if (checkbox.checked) {
                disabled.delete(label);
              } else {
                disabled.add(label);
              }
              await savePatternState();
            });

            const lbl = document.createElement("label");
            lbl.htmlFor = checkbox.id;
            lbl.textContent = label;

            div.appendChild(checkbox);
            div.appendChild(lbl);
            togglesDiv.appendChild(div);
          });
      };

      renderPatterns();

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

    // ==================== CUSTOM SITES (AUTO-SAVE) ====================

    const siteList = document.getElementById("siteList");

    const saveSitesAndRegister = async () => {
      await chrome.storage.local.set({ customSites });

      try {
        if (customSites.length > 0) {
          const origins = customSites.map(s => `*://${s}/*`);
          await chrome.permissions.request({ origins });
        }

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
      } catch (err) {
        console.error("Failed to register sites:", err);
      }
    };

    const renderSites = () => {
      if (!siteList) return;
      siteList.innerHTML = "";

      if (customSites.length === 0) {
        siteList.innerHTML = '<li class="empty-state">No custom sites added</li>';
        return;
      }

      customSites.forEach(site => {
        const li = document.createElement("li");
        li.textContent = site;
        const remove = document.createElement("button");
        remove.textContent = "Remove";
        remove.onclick = async () => {
          customSites.splice(customSites.indexOf(site), 1);
          renderSites();
          await saveSitesAndRegister();
          showNotification("Site removed", "success");
        };
        li.appendChild(remove);
        siteList.appendChild(li);
      });
    };

    renderSites();

    const addSiteBtn = document.getElementById("addSite");
    if (addSiteBtn) {
      addSiteBtn.addEventListener("click", async () => {
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
            await saveSitesAndRegister();
            showNotification("Site added", "success");
          } else if (customSites.includes(host)) {
            showNotification("Site already added", "warning");
          }
        } catch (_) {
          showNotification("Invalid URL format", "error");
        }
      });
    }

    // ==================== EXPORT/IMPORT ====================

    const exportBtn = document.getElementById("exportSettings");
    if (exportBtn) {
      exportBtn.addEventListener("click", async () => {
        const data = await chrome.storage.local.get(["disabledPatterns", "customSites", "useEncryption"]);
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `secret-sanitizer-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showNotification("Settings exported", "success");
      });
    }

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
          showNotification("Settings imported!", "success");
          setTimeout(() => location.reload(), 1000);
        } catch (err) {
          showNotification("Invalid settings file", "error");
        }
      });
    }

    // ==================== KEYBOARD SHORTCUTS ====================

    document.addEventListener("keydown", (e) => {
      if (e.ctrlKey || e.metaKey) {
        switch(e.key.toLowerCase()) {
          case 'enter':
            e.preventDefault();
            actionBtn?.click();
            break;
          case 'd':
            e.preventDefault();
            if (confirm("Delete all stored secrets?")) {
              clearVaultBtn?.click();
            }
            break;
        }
      }
    });

  } catch (err) {
    console.error("Popup error:", err);
  }
});
