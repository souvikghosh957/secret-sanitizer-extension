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
    return await Promise.race([
      new Promise((resolve) => {
        chrome.runtime.sendMessage(
          { action: "decrypt", data: encryptedData },
          (response) => {
            resolve(response?.decrypted || encryptedData);
          }
        );
      }),
      new Promise((resolve) => setTimeout(() => resolve(encryptedData), 3000))
    ]);
  } catch (_) {
    try {
      if (typeof encryptedData === 'string' && !encryptedData.startsWith('[')) {
        const decoded = new TextDecoder().decode(Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0)));
        return JSON.parse(decoded);
      }
    } catch (_) {}
    return encryptedData;
  }
}

// Test sanitization using shared patterns from patterns.js (single source of truth)
function testSanitize(text) {
  const patterns = SHARED_PATTERNS;

  // Phase 1: Collect all matches on original text
  const allMatches = [];
  for (const [pattern, label] of patterns) {
    const regex = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = regex.exec(text)) !== null) {
      if (match[0].length === 0) { regex.lastIndex++; continue; }
      allMatches.push({ start: match.index, end: match.index + match[0].length, label, original: match[0] });
      if (!regex.global) break;
    }
  }

  // Phase 2: Remove overlapping matches (prefer earlier, then longer)
  allMatches.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const filtered = [];
  for (const m of allMatches) {
    if (filtered.length === 0 || m.start >= filtered[filtered.length - 1].end) {
      filtered.push(m);
    }
  }

  // Phase 3: Build masked text
  const parts = [];
  let cursor = 0;
  for (const m of filtered) {
    if (m.start > cursor) parts.push(text.substring(cursor, m.start));
    parts.push(`[${m.label}]`);
    cursor = m.end;
  }
  if (cursor < text.length) parts.push(text.substring(cursor));

  return { maskedText: parts.join(''), count: filtered.length };
}

// Detect if text contains placeholders (unmask mode)
function detectMode(text) {
  // Look for [PLACEHOLDER] patterns from our sanitizer
  const placeholderPattern = /\[(AWS_KEY|GITHUB_TOKEN|JWT|PAN|INDIAN_PHONE|OPENAI_KEY|STRIPE_TEST_KEY|PRIVATE_KEY|API_KEY_FORMAT|PLACEHOLDER_\d+|[A-Z_]+_\d+)\]/;
  return placeholderPattern.test(text) ? 'unmask' : 'test';
}

// ==================== MAIN ====================

document.addEventListener("DOMContentLoaded", async () => {
  try {
    const {
      vault = {},
      stats = { totalBlocked: 0, todayBlocked: 0 },
      disabledPatterns = [],
      customSites = [],
      removedDefaults = [],
      darkMode = null,
      autoDarkMode = true,
      useEncryption = true,
      hasSeenWelcome = false
    } = await chrome.storage.local.get([
      "vault", "stats", "disabledPatterns", "customSites", "removedDefaults",
      "darkMode", "autoDarkMode", "useEncryption", "hasSeenWelcome"
    ]);

    // Site status indicator

    const defaultSites = [
      "chatgpt.com", "claude.ai", "gemini.google.com", "grok.com"
    ];
    const activeDefaults = defaultSites.filter(s => !removedDefaults.includes(s));

    const allProtectedSites = [...activeDefaults, ...customSites];
    const siteStatus = document.getElementById("siteStatus");

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url && siteStatus) {
        const url = new URL(tab.url);
        const hostname = url.hostname;
        const isProtected = allProtectedSites.some(site =>
          hostname === site || hostname.endsWith('.' + site)
        );

        if (isProtected) {
          siteStatus.className = "site-status active";
          siteStatus.textContent = "";
          const dot1 = document.createElement("span");
          dot1.className = "status-dot";
          const text1 = document.createElement("span");
          text1.className = "status-text";
          text1.textContent = "Active on " + hostname;
          siteStatus.appendChild(dot1);
          siteStatus.appendChild(text1);
        } else if (url.protocol.startsWith("http")) {
          siteStatus.className = "site-status inactive clickable";
          siteStatus.textContent = "";
          const dot2 = document.createElement("span");
          dot2.className = "status-dot";
          const text2 = document.createElement("span");
          text2.className = "status-text";
          text2.textContent = "Not active on " + (hostname.length > 20 ? hostname.slice(0,20) + '...' : hostname);
          siteStatus.appendChild(dot2);
          siteStatus.appendChild(text2);
          siteStatus.title = "Click to enable on this site";
          siteStatus.addEventListener("click", () => {
            document.querySelector('[data-tab="settings"]').click();
            setTimeout(() => {
              const sitesAccordion = document.getElementById("sitesAccordion");
              if (sitesAccordion?.classList.contains("collapsed")) {
                document.querySelector('[data-accordion="sites"]')?.click();
              }
              const input = document.getElementById("newSite");
              if (input) {
                input.value = hostname;
                input.focus();
              }
            }, 100);
          });
        } else {
          siteStatus.className = "site-status inactive";
          siteStatus.textContent = "";
          const dot3 = document.createElement("span");
          dot3.className = "status-dot";
          const text3 = document.createElement("span");
          text3.className = "status-text";
          text3.textContent = "Not a web page";
          siteStatus.appendChild(dot3);
          siteStatus.appendChild(text3);
        }
      } else if (siteStatus) {
        siteStatus.className = "site-status inactive";
        siteStatus.textContent = "";
        const dot4 = document.createElement("span");
        dot4.className = "status-dot";
        const text4 = document.createElement("span");
        text4.className = "status-text";
        text4.textContent = "Not a web page";
        siteStatus.appendChild(dot4);
        siteStatus.appendChild(text4);
      }
    } catch (e) {
      if (siteStatus) {
        siteStatus.className = "site-status inactive";
        siteStatus.textContent = "";
        const dot5 = document.createElement("span");
        dot5.className = "status-dot";
        const text5 = document.createElement("span");
        text5.className = "status-text";
        text5.textContent = "Status unavailable";
        siteStatus.appendChild(dot5);
        siteStatus.appendChild(text5);
      }
    }

    // First-run welcome

    const welcomeOverlay = document.getElementById("welcomeOverlay");
    const welcomeStartBtn = document.getElementById("welcomeStart");

    if (!hasSeenWelcome && welcomeOverlay) {
      welcomeOverlay.classList.remove("hidden");
    }

    if (welcomeStartBtn) {
      welcomeStartBtn.addEventListener("click", async () => {
        await chrome.storage.local.set({ hasSeenWelcome: true });
        welcomeOverlay.style.animation = "welcomeFadeOut 0.2s ease-out forwards";
        setTimeout(() => {
          welcomeOverlay.classList.add("hidden");
          welcomeOverlay.style.animation = "";
        }, 200);
      });
    }

    // Show welcome screen again
    const showWelcomeBtn = document.getElementById("showWelcome");
    if (showWelcomeBtn && welcomeOverlay) {
      showWelcomeBtn.addEventListener("click", () => {
        welcomeOverlay.classList.remove("hidden");
        welcomeOverlay.style.animation = "welcomeFade 0.3s ease-out";
      });
    }

    const disabled = new Set(disabledPatterns);
    const now = Date.now();

    // Dark mode

    // Body starts with dark-mode class in HTML (default).
    // Only remove it if the user has explicitly chosen light mode.
    const shouldUseDarkMode = darkMode === null ? true : darkMode === true;

    if (!shouldUseDarkMode) {
      document.body.classList.remove("dark-mode");
    }

    if (autoDarkMode) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (darkMode === null) {
          document.body.classList.toggle("dark-mode", e.matches);
        }
      });
    }

    // Clean expired vault entries

    let cleaned = false;
    Object.keys(vault).forEach(key => {
      if (vault[key] && vault[key].expires < now) {
        delete vault[key];
        cleaned = true;
      }
    });
    if (cleaned) await chrome.storage.local.set({ vault });

    // Hero stats

    const heroTotal = document.getElementById("heroTotal");
    const heroToday = document.getElementById("heroToday");

    if (heroTotal) {
      animateCount(heroTotal, stats.totalBlocked || 0, 800);
    }
    if (heroToday) {
      heroToday.textContent = stats.todayBlocked || 0;
    }

    // Action area

    const actionInput = document.getElementById("actionInput");
    const actionBtn = document.getElementById("actionBtn");
    const actionIcon = document.getElementById("actionIcon");
    const actionBtnText = document.getElementById("actionBtnText");
    const actionOutput = document.getElementById("actionOutput");
    const modeIndicator = document.getElementById("modeIndicator");

    // Update UI based on detected mode
    function updateModeUI(mode) {
      const badge = modeIndicator.querySelector('.mode-badge');

      const buildBadge = (iconClass, text) => {
        badge.textContent = "";
        const i = document.createElement("i");
        i.className = iconClass;
        badge.appendChild(i);
        badge.appendChild(document.createTextNode(" " + text));
      };

      if (mode === 'unmask') {
        actionBtn.classList.add('mode-unmask');
        actionIcon.className = 'fas fa-unlock';
        actionBtnText.textContent = 'Unmask Secrets';
        badge.className = 'mode-badge mode-unmask';
        buildBadge('fas fa-unlock', 'Unmask mode');
      } else if (mode === 'test') {
        actionBtn.classList.remove('mode-unmask');
        actionIcon.className = 'fas fa-vial';
        actionBtnText.textContent = 'Test Masking';
        badge.className = 'mode-badge mode-test';
        buildBadge('fas fa-flask', 'Test mode');
      } else {
        actionBtn.classList.remove('mode-unmask');
        actionIcon.className = 'fas fa-vial';
        actionBtnText.textContent = 'Analyze';
        badge.className = 'mode-badge mode-auto';
        buildBadge('fas fa-robot', 'Auto-detect');
      }
    }

    // Example snippets for "Try it" buttons
    const EXAMPLES = {
      password: `Here's my database config:\npassword: SuperSecret123!\nPlease help me debug the connection.`,
      // Sample key from Stripe docs (https://docs.stripe.com/keys) — not a real secret
      apikey: `I'm getting an error with this code:\nconst stripe = require('stripe')('sk_live_4eC39HqLyjWDarjtT1zdp7dc');\nWhat am I doing wrong?`,
      full: `My .env file looks like this:\nOPENAI_KEY=sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghijklmn\nDB_URL=postgres://admin:P@ssw0rd123@db.example.com:5432/myapp\npassword: MyS3cretP@ss!\nCan you review this for security issues?`
    };

    // Wire up "Try it" buttons
    document.querySelectorAll('.try-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const example = EXAMPLES[btn.dataset.example];
        if (example && actionInput) {
          actionInput.value = example;
          actionInput.dispatchEvent(new Event('input', { bubbles: true }));
          actionInput.focus();
          // Auto-click analyze after a brief moment
          setTimeout(() => actionBtn?.click(), 150);
        }
      });
    });

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
        if (actionBtn.disabled) return;
        const text = actionInput?.value.trim();
        if (!text) {
          showNotification("Paste some text first", "warning");
          return;
        }

        actionBtn.disabled = true;
        actionBtn.classList.add('loading');
        const mode = detectMode(text);

        if (mode === 'unmask') {
          // Unmask mode
          let unmasked = text;
          let replacedCount = 0;

          const currentTime = Date.now();
          for (const entry of Object.values(vault)) {
            if (!entry || entry.expires < currentTime) continue;

            let replacements = entry.replacements;
            if (entry.encrypted) {
              try {
                replacements = await decryptData({ encrypted: true, data: replacements });
              } catch (err) {
                console.warn("Decryption error:", err);
                continue;
              }
            } else if (typeof replacements === 'string' && !replacements.startsWith('[')) {
              try {
                replacements = await decryptData({ encrypted: false, data: replacements });
              } catch (err) {}
            }

            if (!Array.isArray(replacements)) continue;
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

            actionBtn.classList.remove('loading');
            actionBtn.disabled = false;
          });
          return; // button re-enabled inside rAF
        }

        actionBtn.classList.remove('loading');
        actionBtn.disabled = false;
      });
    }

    // Recent section

    const recentList = document.getElementById("recentList");
    const recentListExpanded = document.getElementById("recentListExpanded");
    const recentExpanded = document.getElementById("recentExpanded");
    const toggleExpandBtn = document.getElementById("toggleRecentExpand");
    const vaultSearch = document.getElementById("vaultSearch");

    const renderRecent = (targetList, limit = 3, searchTerm = "") => {
      if (!targetList) return;
      targetList.replaceChildren();

      let traceIds = Object.keys(vault)
        .filter(id => {
          if (!searchTerm) return true;
          return id.toLowerCase().includes(searchTerm.toLowerCase());
        })
        .sort((a, b) => (vault[b]?.expires || 0) - (vault[a]?.expires || 0))
        .slice(0, limit);

      if (traceIds.length === 0) {
        const emptyLi = document.createElement("li");
        emptyLi.className = "empty-state";
        emptyLi.textContent = searchTerm ? 'No matches' : 'No recent sanitizations';
        targetList.appendChild(emptyLi);
      } else {
        traceIds.forEach(id => {
          const entry = vault[id];
          if (!entry) return;
          const minsLeft = Math.max(1, Math.round((entry.expires - Date.now()) / 60000));
          const count = entry.encrypted
            ? (typeof entry.replacements === 'string' ? '?' : entry.replacements?.length || 0)
            : (Array.isArray(entry.replacements) ? entry.replacements.length : 0);
          const li = document.createElement("li");
          li.className = "vault-item";
          const contentDiv = document.createElement("div");
          contentDiv.className = "vault-item-content";
          const strong = document.createElement("strong");
          strong.textContent = id.slice(0, 8) + "...";
          const rightDiv = document.createElement("div");
          const badgeSpan = document.createElement("span");
          badgeSpan.className = "vault-badge";
          badgeSpan.textContent = count;
          const small = document.createElement("small");
          small.style.marginLeft = "8px";
          small.textContent = minsLeft + "m";
          rightDiv.appendChild(badgeSpan);
          rightDiv.appendChild(small);
          contentDiv.appendChild(strong);
          contentDiv.appendChild(rightDiv);
          li.appendChild(contentDiv);
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

    // Dark mode toggle

    const darkModeToggle = document.getElementById("darkModeToggle");
    if (darkModeToggle) {
      // Sync icon with actual state
      const isDark = document.body.classList.contains("dark-mode");
      darkModeToggle.querySelector("i").className = isDark ? "fas fa-sun" : "fas fa-moon";

      darkModeToggle.addEventListener("click", async () => {
        const currentMode = document.body.classList.contains("dark-mode");
        const newMode = !currentMode;
        await chrome.storage.local.set({ darkMode: newMode });
        document.body.classList.toggle("dark-mode", newMode);
        darkModeToggle.querySelector("i").className = newMode ? "fas fa-sun" : "fas fa-moon";
      });
    }

    // Share button

    const shareBtn = document.getElementById("shareBtn");
    if (shareBtn) {
      shareBtn.addEventListener("click", async () => {
        const shareUrl = "https://chromewebstore.google.com/detail/secret-sanitizer/genolcmpopiemhpbdnhkaefllchgekja";
        const shareText = "Secret Sanitizer - Masks API keys, passwords & tokens before they reach AI chats. 100% local, zero tracking.";

        try {
          await navigator.clipboard.writeText(shareUrl);
          showNotification("Link copied! Share it with others", "success");
          // Visual feedback on the button
          const icon = shareBtn.querySelector("i");
          icon.className = "fas fa-check";
          setTimeout(() => { icon.className = "fas fa-share-alt"; }, 2000);
        } catch (_) {
          // Fallback: open share dialog if available
          try {
            await navigator.share({ title: "Secret Sanitizer", text: shareText, url: shareUrl });
          } catch (_) {
            showNotification("Could not copy link", "warning");
          }
        }
      });
    }

    // Tab switching

    document.querySelectorAll(".tab-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".tab-btn").forEach(b => {
          b.classList.remove("active");
          b.setAttribute("aria-selected", "false");
        });
        document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
        btn.classList.add("active");
        btn.setAttribute("aria-selected", "true");
        document.getElementById(`${btn.dataset.tab}-tab`).classList.add("active");
      });
    });

    // Accordion behavior

    document.querySelectorAll('.accordion-header').forEach(header => {
      header.addEventListener('click', () => {
        const accordion = header.closest('.accordion');
        accordion.classList.toggle('collapsed');
        const isExpanded = !accordion.classList.contains('collapsed');
        header.setAttribute('aria-expanded', String(isExpanded));
      });
    });

    // Settings (auto-save)

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

    // Pattern toggles (auto-save)

    const allLabels = [
      // Cloud
      "AWS_KEY","AWS_TEMP_KEY","AZURE_SECRET","GOOGLE_API_KEY",
      // VCS & CI/CD
      "GITHUB_TOKEN","GITHUB_FINE_PAT","GITLAB_TOKEN","GITLAB_TRIGGER_TOKEN",
      // Auth & Tokens
      "JWT","BEARER_TOKEN","PASSWORD_HINT","OTP_CODE","EMAIL_IN_SECRET",
      // Database
      "DB_CONN",
      // Credit Cards
      "CREDIT_CARD",
      // Payments
      "STRIPE_KEY","STRIPE_TEST_KEY","STRIPE_PUB_KEY","STRIPE_TEST_PUB_KEY",
      "SQUARE_ACCESS_TOKEN","SQUARE_SECRET",
      "RAZORPAY_KEY","RAZORPAY_TEST_KEY",
      "PAYTM_KEY","PAYTM_MERCHANT",
      // Communication
      "TWILIO_SID","TWILIO_AUTH_TOKEN",
      "SLACK_TOKEN","DISCORD_WEBHOOK","TELEGRAM_BOT_TOKEN",
      "SENDGRID_KEY","MAILGUN_KEY",
      // AI & ML
      "OPENAI_KEY","ANTHROPIC_KEY","GROQ_KEY","HUGGINGFACE_TOKEN",
      // Cloud Platforms
      "FIREBASE_KEY","HEROKU_API_KEY","VERCEL_TOKEN",
      "DIGITALOCEAN_TOKEN","DIGITALOCEAN_REFRESH",
      "SUPABASE_TOKEN","CLOUDFLARE_TOKEN","DATADOG_KEY",
      // E-Commerce
      "SHOPIFY_TOKEN",
      // Package Registries
      "NPM_TOKEN","PYPI_TOKEN",
      // Indian PII
      "AADHAAR","PAN","INDIAN_PHONE","GSTIN","IFSC",
      "UPI_ID","UPI_ID_GENERIC","UPI_TEST_ID","PAYMENT_UPI_ID",
      "DRIVING_LICENSE","VOTER_ID","PASSPORT","VEHICLE_REG",
      // Key=Value Formats
      "API_KEY_FORMAT","SECRET_KEY_FORMAT","ACCESS_KEY_FORMAT","AUTH_SECRET_FORMAT",
      // Private Keys
      "PRIVATE_KEY","SSH_PRIVATE_KEY","PGP_PRIVATE_KEY",
      // Generic Fallbacks
      "QUOTED_SECRET","LONG_RANDOM_STRING","BASE64_SECRET"
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
        togglesDiv.replaceChildren();
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

    // Custom sites (auto-save)

    const updateNoSitesWarning = () => {
      const warning = document.getElementById("noSitesWarning");
      if (!warning) return;
      const active = activeDefaults.length + customSites.length;
      warning.classList.toggle("hidden", active > 0);
    };

    const saveSitesAndRegister = async () => {
      // Save first — if the permission prompt closes the popup, data is still persisted
      await chrome.storage.local.set({ customSites, removedDefaults });
      updateNoSitesWarning();

      try {
        if (customSites.length > 0) {
          const origins = customSites.map(s => `*://${s}/*`);
          await chrome.permissions.request({ origins });
        }
      } catch (_) {}
    };

    const renderSiteChips = () => {
      const container = document.getElementById("siteChips");
      if (!container) return;
      container.textContent = "";

      // Default site chips
      defaultSites.forEach(site => {
        const isActive = !removedDefaults.includes(site);
        const chip = document.createElement("span");
        chip.className = "site-chip " + (isActive ? "active" : "removed");
        const siteText = document.createTextNode(site + " ");
        chip.appendChild(siteText);
        const btn = document.createElement("button");
        btn.title = isActive ? "Remove" : "Restore";
        btn.textContent = isActive ? "\u00d7" : "+";
        btn.onclick = async () => {
          if (isActive) {
            removedDefaults.push(site);
            activeDefaults.splice(activeDefaults.indexOf(site), 1);
            showNotification(site + " removed", "success");
          } else {
            removedDefaults.splice(removedDefaults.indexOf(site), 1);
            activeDefaults.push(site);
            showNotification(site + " restored", "success");
          }
          renderSiteChips();
          await saveSitesAndRegister();
        };
        chip.appendChild(btn);
        container.appendChild(chip);
      });

      // Custom site chips
      customSites.forEach(site => {
        const chip = document.createElement("span");
        chip.className = "site-chip custom active";
        const siteText = document.createTextNode(site + " ");
        chip.appendChild(siteText);
        const btn = document.createElement("button");
        btn.title = "Remove";
        btn.textContent = "\u00d7";
        btn.onclick = async () => {
          customSites.splice(customSites.indexOf(site), 1);
          renderSiteChips();
          await saveSitesAndRegister();
          showNotification("Site removed", "success");
        };
        chip.appendChild(btn);
        container.appendChild(chip);
      });
    };

    renderSiteChips();
    updateNoSitesWarning();

    const newSiteInput = document.getElementById("newSite");
    if (newSiteInput) {
      newSiteInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          document.getElementById("addSite")?.click();
        }
      });
    }

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

          if (defaultSites.includes(host)) {
            showNotification("Use the + button above to restore this default", "warning");
          } else if (customSites.includes(host)) {
            showNotification("Site already added", "warning");
          } else if (host) {
            customSites.push(host);
            input.value = "";
            renderSiteChips();
            await saveSitesAndRegister();
            showNotification("Site added", "success");
          }
        } catch (_) {
          showNotification("Invalid URL format", "error");
        }
      });
    }

    // Export/Import

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

          // Only import known safe settings keys
          const allowedKeys = ["disabledPatterns", "customSites", "useEncryption", "autoDarkMode", "darkMode"];
          const safeData = {};
          for (const key of allowedKeys) {
            if (key in data) safeData[key] = data[key];
          }

          if (Object.keys(safeData).length === 0) {
            showNotification("No valid settings found in file", "warning");
            return;
          }

          await chrome.storage.local.set(safeData);
          showNotification("Settings imported!", "success");
          setTimeout(() => location.reload(), 1000);
        } catch (err) {
          showNotification("Invalid settings file", "error");
        }
      });
    }

    // Keyboard shortcuts

    document.addEventListener("keydown", (e) => {
      if (e.ctrlKey || e.metaKey) {
        switch(e.key.toLowerCase()) {
          case 'enter':
            e.preventDefault();
            actionBtn?.click();
            break;
          case 'd':
            if (e.shiftKey) {
              e.preventDefault();
              clearVaultBtn?.click();
            }
            break;
        }
      }
    });

  } catch (err) {
    console.warn("Popup initialization error:", err);
  }
});
