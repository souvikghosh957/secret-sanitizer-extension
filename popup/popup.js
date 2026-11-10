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

// Test masking with the same engine the content script uses (detector.js + patterns.js),
// honouring the user's disabled patterns and allowed values so the result matches what a real paste does.
function testSanitize(text, disabledLabels, allowedHashes, allowSalt) {
  const { matches: found } = findSecrets(text, compilePatterns(SHARED_PATTERNS, disabledLabels));
  const matches = dropAllowedValues(found, allowedHashes, allowSalt);
  const { maskedText, replacements } = maskText(text, matches, (label) => `[${label}]`);
  return { maskedText, count: replacements.length };
}

// Detect if text contains placeholders produced by a paste (unmask mode)
function detectMode(text) {
  return PLACEHOLDER_TEST_RE.test(text) ? 'unmask' : 'test';
}

// ==================== MAIN ====================

document.addEventListener("DOMContentLoaded", async () => {
  localizePage();
  try {
    const {
      stats = { totalBlocked: 0, todayBlocked: 0 },
      disabledPatterns = [],
      customSites: storedCustomSites = [],
      removedDefaults = [],
      darkMode = null,
      autoDarkMode = true,
      hasSeenWelcome = false,
      weeklyReport = false,
      allowedValues = [],
      allowSalt = null,
      pausedUntil,
      pausedSites = []
    } = await chrome.storage.local.get([
      "stats", "disabledPatterns", "customSites", "removedDefaults",
      "darkMode", "autoDarkMode", "hasSeenWelcome", "weeklyReport",
      "allowedValues", "allowSalt", "pausedUntil", "pausedSites"
    ]);
    // The vault is memory-only (chrome.storage.session), owned by the background worker
    const { vault = {} } = await chrome.storage.session.get("vault");
    const customSites = (Array.isArray(storedCustomSites) ? storedCustomSites : [])
      .map(normalizeSite).filter(Boolean);

    // Site status indicator

    const defaultSites = DEFAULT_SITES;
    const activeDefaults = defaultSites.filter(s => !removedDefaults.includes(s));

    // Host permission is the source of truth for custom sites: it can be denied, or revoked
    // from chrome://extensions, while the site is still in the list.
    const sitesMissingPermission = new Set();
    await Promise.all(customSites.map(async (site) => {
      if (!await chrome.permissions.contains({ origins: [siteMatchPattern(site)] })) sitesMissingPermission.add(site);
    }));

    const allProtectedSites = [...activeDefaults, ...customSites.filter(s => !sitesMissingPermission.has(s))];
    const siteStatus = document.getElementById("siteStatus");

    const setSiteStatus = (className, text) => {
      if (!siteStatus) return;
      siteStatus.className = `site-status ${className}`;
      siteStatus.textContent = "";
      const dot = document.createElement("span");
      dot.className = "status-dot";
      const label = document.createElement("span");
      label.className = "status-text";
      label.textContent = text;
      siteStatus.appendChild(dot);
      siteStatus.appendChild(label);
    };

    // Hostname of the active tab when it's a protected site, for the "pause on this site" button
    let protectedHost = null;
    const pause = { pausedUntil, pausedSites: Array.isArray(pausedSites) ? pausedSites : [] };

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const url = tab?.url ? new URL(tab.url) : null;
      if (url && allProtectedSites.some(site => url.hostname === siteHostname(site))) {
        protectedHost = url.hostname;
      } else if (url && url.protocol.startsWith("http")) {
        const hostname = url.hostname;
        setSiteStatus("inactive clickable", t("status_not_active", [hostname.length > 20 ? hostname.slice(0, 20) + '...' : hostname]));
        siteStatus.title = t("status_enable_hint");
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
        setSiteStatus("inactive", t("status_not_web"));
      }
    } catch (e) {
      setSiteStatus("inactive", t("status_unavailable"));
    }

    // Pause

    const pauseState = document.getElementById("pauseState");
    const pauseTimedBtn = document.getElementById("pauseTimed");
    const pauseSiteBtn = document.getElementById("pauseSite");
    const resumeBtn = document.getElementById("resumeBtn");

    const renderPause = () => {
      const timed = isPaused({ pausedUntil: pause.pausedUntil });
      const sitePaused = protectedHost !== null && pause.pausedSites.includes(protectedHost);
      if (protectedHost) {
        setSiteStatus(timed || sitePaused ? "inactive" : "active",
          t(timed || sitePaused ? "status_paused_on" : "status_active", [protectedHost]));
      }
      let message = "";
      if (timed) {
        message = t("pause_state_timed", [String(Math.max(1, Math.ceil((pause.pausedUntil - Date.now()) / 60000)))]);
      } else if (sitePaused) {
        message = t("pause_state_site", [protectedHost]);
      }
      pauseState.textContent = message;
      pauseState.classList.toggle("hidden", !message);
      pauseTimedBtn.classList.toggle("hidden", timed);
      pauseSiteBtn.classList.toggle("hidden", !protectedHost || sitePaused);
      resumeBtn.classList.toggle("hidden", !timed && !sitePaused);
    };

    pauseTimedBtn.addEventListener("click", async () => {
      pause.pausedUntil = Date.now() + PAUSE_DURATION_MS;
      await chrome.storage.local.set({ pausedUntil: pause.pausedUntil });
      renderPause();
    });
    pauseSiteBtn.addEventListener("click", async () => {
      pause.pausedSites = [...new Set([...pause.pausedSites, protectedHost])];
      await chrome.storage.local.set({ pausedSites: pause.pausedSites });
      renderPause();
    });
    resumeBtn.addEventListener("click", async () => {
      pause.pausedUntil = undefined;
      pause.pausedSites = pause.pausedSites.filter(s => s !== protectedHost);
      await chrome.storage.local.remove("pausedUntil");
      await chrome.storage.local.set({ pausedSites: pause.pausedSites });
      renderPause();
    });
    renderPause();
    setInterval(renderPause, 15000); // keeps the countdown honest while the popup is open

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

    // Hide expired vault entries (the background worker owns deletion, so the popup
    // never rewrites the vault and can't race a paste being saved)

    Object.keys(vault).forEach(key => {
      if (!vault[key] || vault[key].expires < now) delete vault[key];
    });

    // Hero stats

    const heroTotal = document.getElementById("heroTotal");
    const heroToday = document.getElementById("heroToday");

    if (heroTotal) {
      animateCount(heroTotal, stats.totalBlocked || 0, 800);
    }
    if (heroToday) {
      // todayBlocked is only reset on the next paste — don't show yesterday's count
      heroToday.textContent = stats.lastDate === new Date().toDateString() ? (stats.todayBlocked || 0) : 0;
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
        actionBtnText.textContent = t("action_unmask");
        badge.className = 'mode-badge mode-unmask';
        buildBadge('fas fa-unlock', t("mode_unmask"));
      } else if (mode === 'test') {
        actionBtn.classList.remove('mode-unmask');
        actionIcon.className = 'fas fa-vial';
        actionBtnText.textContent = t("action_test");
        badge.className = 'mode-badge mode-test';
        buildBadge('fas fa-flask', t("mode_test"));
      } else {
        actionBtn.classList.remove('mode-unmask');
        actionIcon.className = 'fas fa-vial';
        actionBtnText.textContent = t("action_analyze");
        badge.className = 'mode-badge mode-auto';
        buildBadge('fas fa-robot', t("mode_auto"));
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
          showNotification(t("note_paste_first"), "warning");
          return;
        }

        actionBtn.disabled = true;
        actionBtn.classList.add('loading');
        const mode = detectMode(text);

        if (mode === 'unmask') {
          // Unmask mode
          const currentTime = Date.now();
          const originals = new Map();
          for (const entry of Object.values(vault)) {
            if (!entry || entry.expires < currentTime || !Array.isArray(entry.replacements)) continue;
            for (const [placeholder, original] of entry.replacements) originals.set(placeholder, original);
          }

          const found = new Set();
          const unmasked = text.replace(new RegExp(PLACEHOLDER_SOURCE, "g"), (token) => {
            if (!originals.has(token)) return token;
            found.add(token);
            return originals.get(token);
          });
          const replacedCount = found.size;

          actionOutput.textContent = unmasked;
          actionOutput.classList.remove('hidden');

          if (replacedCount > 0) {
            showNotification(t("note_unmasked", [String(replacedCount)]), "success");
          } else {
            showNotification(t("note_no_placeholders"), "warning");
          }
        } else {
          // Test mode
          requestAnimationFrame(() => {
            const result = testSanitize(text, disabled, new Set(allowedHashes), allowSalt);
            actionOutput.textContent = result.maskedText;
            actionOutput.classList.remove('hidden');

            if (result.count > 0) {
              showNotification(t("note_found", [String(result.count)]), "success");
            } else {
              showNotification(t("note_none_found"), "warning");
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
          const term = searchTerm.toLowerCase();
          return id.toLowerCase().includes(term) || (vault[id]?.origin || "").toLowerCase().includes(term);
        })
        .sort((a, b) => (vault[b]?.expires || 0) - (vault[a]?.expires || 0))
        .slice(0, limit);

      if (traceIds.length === 0) {
        const emptyLi = document.createElement("li");
        emptyLi.className = "empty-state";
        emptyLi.textContent = t(searchTerm ? "recent_no_matches" : "recent_empty");
        targetList.appendChild(emptyLi);
      } else {
        traceIds.forEach(id => {
          const entry = vault[id];
          if (!entry) return;
          const minsLeft = Math.max(1, Math.round((entry.expires - Date.now()) / 60000));
          const count = Array.isArray(entry.replacements) ? entry.replacements.length : 0;
          const li = document.createElement("li");
          li.className = "vault-item";
          const contentDiv = document.createElement("div");
          contentDiv.className = "vault-item-content";
          const strong = document.createElement("strong");
          let site = "";
          try { site = new URL(entry.origin).hostname; } catch (_) {}
          strong.textContent = site || id.slice(0, 8) + "...";
          strong.title = id;
          const rightDiv = document.createElement("div");
          const badgeSpan = document.createElement("span");
          badgeSpan.className = "vault-badge";
          badgeSpan.textContent = count;
          const small = document.createElement("small");
          small.style.marginLeft = "8px";
          small.textContent = t("recent_minutes", [String(minsLeft)]);
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
        const shareText = t("share_text");

        try {
          await navigator.clipboard.writeText(shareUrl);
          showNotification(t("note_link_copied"), "success");
          // Visual feedback on the button
          const icon = shareBtn.querySelector("i");
          icon.className = "fas fa-check";
          setTimeout(() => { icon.className = "fas fa-share-alt"; }, 2000);
        } catch (_) {
          // Fallback: open share dialog if available
          try {
            await navigator.share({ title: "Secret Sanitizer", text: shareText, url: shareUrl });
          } catch (_) {
            showNotification(t("note_link_failed"), "warning");
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
        showNotification(t(e.target.checked ? "note_auto_dark_on" : "note_auto_dark_off"), "success");
      });
    }

    const weeklyReportCheckbox = document.getElementById("weeklyReport");
    if (weeklyReportCheckbox) {
      weeklyReportCheckbox.checked = weeklyReport === true;
      weeklyReportCheckbox.addEventListener("change", async (e) => {
        await chrome.storage.local.set({ weeklyReport: e.target.checked });
      });
    }

    // Delete secrets — two-step inline confirmation to avoid unreliable confirm() in extensions
    const clearVaultBtn = document.getElementById("clearVault");
    const setVaultBtnLabel = (icon, text) => {
      clearVaultBtn.querySelector("i").className = icon;
      document.getElementById("clearVaultText").textContent = text;
    };
    if (clearVaultBtn) {
      clearVaultBtn.addEventListener("click", async () => {
        if (clearVaultBtn.dataset.confirming !== "true") {
          // First click: arm the button
          clearVaultBtn.dataset.confirming = "true";
          setVaultBtnLabel("fas fa-exclamation-triangle", t("vault_confirm"));
          clearVaultBtn.classList.add("btn-danger");
          clearVaultBtn._confirmTimer = setTimeout(() => {
            clearVaultBtn.dataset.confirming = "";
            setVaultBtnLabel("fas fa-eraser", t("vault_delete_all"));
            clearVaultBtn.classList.remove("btn-danger");
          }, 3000);
          return;
        }
        // Second click: execute delete
        clearTimeout(clearVaultBtn._confirmTimer);
        clearVaultBtn.dataset.confirming = "";
        setVaultBtnLabel("fas fa-eraser", t("vault_delete_all"));
        clearVaultBtn.classList.remove("btn-danger");
        await chrome.storage.session.set({ vault: {} });
        showNotification(t("note_vault_deleted"), "success");
        setTimeout(() => location.reload(), 500);
      });
    }

    // Allowed values — only salted hashes are stored, so they can be counted and cleared but not listed

    let allowedHashes = Array.isArray(allowedValues) ? allowedValues : [];
    const allowedCount = document.getElementById("allowedCount");
    const clearAllowedBtn = document.getElementById("clearAllowed");
    const renderAllowedCount = () => {
      allowedCount.textContent = t("allowed_count", [String(allowedHashes.length)]);
      clearAllowedBtn.disabled = allowedHashes.length === 0;
    };
    renderAllowedCount();
    clearAllowedBtn.addEventListener("click", async () => {
      allowedHashes = [];
      await chrome.storage.local.remove(["allowedValues", "allowSalt"]);
      renderAllowedCount();
      showNotification(t("note_allowed_cleared"), "success");
    });

    // Pattern toggles (auto-save)

    // Derive labels from the single source of truth in patterns.js — no manual sync needed.
    // Random-token detection isn't a regex, so it's listed separately.
    const allLabels = [...new Set(SHARED_PATTERNS.map(([, label]) => label)), "ENTROPY"];

    const togglesDiv = document.getElementById("patternToggles");

    if (togglesDiv) {
      const renderPatterns = (search = "") => {
        togglesDiv.replaceChildren();
        allLabels
          .filter(l => `${l} ${patternName(l)} ${PATTERN_EXAMPLES[l] || ""}`.toLowerCase().includes(search.toLowerCase()))
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
              // The whole set, not the checkboxes: a search hides most of them
              await chrome.storage.local.set({ disabledPatterns: [...disabled] });
            });

            const lbl = document.createElement("label");
            lbl.htmlFor = checkbox.id;
            lbl.title = label; // internal name, as it appears in placeholders
            lbl.textContent = patternName(label);

            if (GENERIC_LABELS.has(label)) {
              const tag = document.createElement("span");
              tag.className = "pattern-warn";
              tag.title = t("patterns_generic_title");
              tag.textContent = t("patterns_generic_tag");
              lbl.appendChild(tag);
            }

            const example = document.createElement("small");
            example.className = "pattern-example";
            example.textContent = PATTERN_EXAMPLES[label] || "";

            div.appendChild(checkbox);
            div.appendChild(lbl);
            div.appendChild(example);
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
      const active = activeDefaults.length + customSites.filter(s => !sitesMissingPermission.has(s)).length;
      warning.classList.toggle("hidden", active > 0);
    };

    const saveSites = async () => {
      await chrome.storage.local.set({ customSites, removedDefaults });
      updateNoSitesWarning();
    };

    // Chrome only shows the prompt during the click's user gesture, and the prompt can close the
    // popup, ending this code. So the save and the request start together; a site whose permission
    // never arrived shows as "needs permission" next time, rather than as protected.
    const requestSitePermission = async (site) => {
      try {
        return await chrome.permissions.request({ origins: [siteMatchPattern(site)] });
      } catch (err) {
        console.warn("[SecretSanitizer] Permission request failed:", err);
        return false;
      }
    };

    const addCustomSite = async (site) => {
      customSites.push(site);
      sitesMissingPermission.add(site);
      renderSiteChips();
      const saved = saveSites();
      const granted = await requestSitePermission(site);
      await saved;
      if (granted) {
        sitesMissingPermission.delete(site);
        renderSiteChips();
        showNotification(t("note_site_added"), "success");
      } else {
        customSites.splice(customSites.indexOf(site), 1);
        sitesMissingPermission.delete(site);
        renderSiteChips();
        await saveSites();
        showNotification(t("note_site_denied"), "error");
      }
    };

    const renderSiteChips = () => {
      updateNoSitesWarning();
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
        btn.title = t(isActive ? "sites_remove" : "sites_restore");
        btn.textContent = isActive ? "\u00d7" : "+";
        btn.onclick = async () => {
          if (isActive) {
            removedDefaults.push(site);
            activeDefaults.splice(activeDefaults.indexOf(site), 1);
            showNotification(t("note_site_removed", [site]), "success");
          } else {
            removedDefaults.splice(removedDefaults.indexOf(site), 1);
            activeDefaults.push(site);
            showNotification(t("note_site_restored", [site]), "success");
          }
          renderSiteChips();
          await saveSites();
        };
        chip.appendChild(btn);
        container.appendChild(chip);
      });

      // Custom site chips
      customSites.forEach(site => {
        const chip = document.createElement("span");
        const missing = sitesMissingPermission.has(site);
        chip.className = "site-chip custom " + (missing ? "missing" : "active");
        const siteText = document.createTextNode(site + " ");
        chip.appendChild(siteText);
        if (missing) {
          chip.title = t("sites_needs_permission");
          chip.addEventListener("click", async () => {
            if (await requestSitePermission(site)) {
              sitesMissingPermission.delete(site);
              renderSiteChips();
              showNotification(t("note_site_added"), "success");
            }
          });
        }
        const btn = document.createElement("button");
        btn.title = t("sites_remove");
        btn.textContent = "\u00d7";
        btn.onclick = async (e) => {
          e.stopPropagation();
          customSites.splice(customSites.indexOf(site), 1);
          sitesMissingPermission.delete(site);
          renderSiteChips();
          await saveSites();
          // Least privilege: don't keep access to a site we no longer protect
          let released = true;
          if (!customSites.some(s => siteHostname(s) === siteHostname(site))) {
            released = await chrome.permissions.remove({ origins: [siteMatchPattern(site)] }).catch(() => false);
          }
          if (released) {
            showNotification(t("note_site_removed", [site]), "success");
          } else {
            showNotification(t("note_site_remove_incomplete", [site]), "warning");
          }
        };
        chip.appendChild(btn);
        container.appendChild(chip);
      });

      // One-click opt-ins for other AI chats
      const suggestions = SUGGESTED_SITES.filter(s => !customSites.includes(s));
      document.getElementById("suggestedSites").classList.toggle("hidden", suggestions.length === 0);
      const suggestedChips = document.getElementById("suggestedChips");
      suggestedChips.textContent = "";
      suggestions.forEach(site => {
        const chip = document.createElement("button");
        chip.className = "site-chip suggested";
        chip.textContent = "+ " + site.replace(/^www\./, "");
        chip.title = t("sites_add_named", [site]);
        chip.addEventListener("click", () => addCustomSite(site));
        suggestedChips.appendChild(chip);
      });
    };

    renderSiteChips();

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

        const urlStr = input.value.trim();
        if (!urlStr) return;

        const host = normalizeSite(urlStr);
        if (!host) {
          showNotification(t("note_site_invalid"), "error");
        } else if (defaultSites.includes(host)) {
          showNotification(t("note_site_default"), "warning");
        } else if (customSites.includes(host)) {
          showNotification(t("note_site_exists"), "warning");
        } else {
          input.value = "";
          await addCustomSite(host);
        }
      });
    }

    // Export/Import

    const exportBtn = document.getElementById("exportSettings");
    if (exportBtn) {
      exportBtn.addEventListener("click", async () => {
        // Allowed-value hashes and pause state stay out: a settings file shouldn't turn masking off elsewhere
        const data = await chrome.storage.local.get(["disabledPatterns", "customSites", "removedDefaults", "autoDarkMode", "darkMode", "weeklyReport"]);
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `secret-sanitizer-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showNotification(t("note_exported"), "success");
      });
    }

    const importBtn = document.getElementById("importSettings");
    const importFile = document.getElementById("importFile");
    if (importBtn && importFile) {
      importBtn.addEventListener("click", () => importFile.click());
      importFile.addEventListener("change", async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        if (file.size > 100 * 1024) {
          showNotification(t("note_import_too_large"), "error");
          e.target.value = "";
          return;
        }

        try {
          const text = await file.text();
          const data = JSON.parse(text);

          // Only import known safe settings keys with type validation
          const safeData = {};
          // Only rules this version knows, so a file can't fill storage with junk labels
          if (Array.isArray(data.disabledPatterns)) {
            safeData.disabledPatterns = [...new Set(data.disabledPatterns.filter(p => allLabels.includes(p)))];
          }
          // Sites are normalized + validated so a malformed entry can't break registration
          if (Array.isArray(data.customSites)) {
            safeData.customSites = [...new Set(data.customSites.map(normalizeSite).filter(Boolean))]
              .filter(s => !DEFAULT_SITES.includes(s));
          }
          if (Array.isArray(data.removedDefaults)) safeData.removedDefaults = data.removedDefaults.filter(s => DEFAULT_SITES.includes(s));
          if (typeof data.autoDarkMode === 'boolean') safeData.autoDarkMode = data.autoDarkMode;
          if (typeof data.darkMode === 'boolean') safeData.darkMode = data.darkMode;
          if (typeof data.weeklyReport === 'boolean') safeData.weeklyReport = data.weeklyReport;

          if (Object.keys(safeData).length === 0) {
            showNotification(t("note_import_empty"), "warning");
            return;
          }

          await chrome.storage.local.set(safeData);
          showNotification(t("note_imported"), "success");
          setTimeout(() => location.reload(), 1000);
        } catch (err) {
          showNotification(t("note_import_invalid"), "error");
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
