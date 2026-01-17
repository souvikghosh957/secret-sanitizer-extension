// popup.js - All patterns ENABLED by default
// User can disable (uncheck) any they don't want
// Safe but powerful: Core secrets masked out-of-box, user can opt-out

document.addEventListener("DOMContentLoaded", async () => {
  console.log("🛡️ Secret Sanitizer popup opened");

  try {
    const { vault = {}, stats = { totalBlocked: 0, todayBlocked: 0 }, disabledPatterns = [], customSites = [] } = await chrome.storage.local.get(["vault", "stats", "disabledPatterns", "customSites"]);
    const disabled = new Set(disabledPatterns);

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

    // Recent
    const recentList = document.getElementById("recentList");
    if (recentList) {
      recentList.innerHTML = "";
      const traceIds = Object.keys(vault)
        .sort((a, b) => (vault[b]?.expires || 0) - (vault[a]?.expires || 0))
        .slice(0, 10);

      if (traceIds.length === 0) {
        recentList.innerHTML = "<li>No recent sanitizations</li>";
      } else {
        traceIds.forEach(id => {
          const entry = vault[id];
          if (!entry) return;
          const minsLeft = Math.max(1, Math.round((entry.expires - now) / 60000));
          const li = document.createElement("li");
          li.innerHTML = `<strong>${id.slice(0, 8)}...</strong><br>
                          <small>${entry.replacements.length} secrets • ${minsLeft} min left</small>`;
          recentList.appendChild(li);
        });
      }
    }

    // Unmask
    document.getElementById("unmaskBtn").addEventListener("click", () => {
      const text = document.getElementById("inputText").value.trim();
      if (!text) return alert("Paste response first!");

      let unmasked = text;
      let replacedCount = 0;

      for (const entry of Object.values(vault)) {
        if (!entry || entry.expires < now) continue;
        for (const [placeholder, original] of entry.replacements) {
          const escaped = placeholder.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const regex = new RegExp(escaped, "g");
          if (regex.test(unmasked)) {
            unmasked = unmasked.replace(regex, original);
            replacedCount++;
          }
        }
      }

      const output = document.getElementById("output");
      output.textContent = replacedCount > 0 ? unmasked : "No placeholders found.";
      output.classList.remove("hidden");
    });

    // Tab switching
    document.querySelectorAll(".tab-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
        document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
        btn.classList.add("active");
        document.getElementById(`${btn.dataset.tab}-tab`).classList.add("active");
      });
    });

    // Patterns (all ENABLED by default)
    const allLabels = ["AWS_KEY","AWS_TEMP_KEY","GITHUB_TOKEN","JWT","DB_CONN","CREDIT_CARD","AADHAAR","PAN","INDIAN_PHONE","GSTIN","IFSC","UPI_ID","UPI_ID_GENERIC","DRIVING_LICENSE","VOTER_ID","BANK_ACCOUNT","EMAIL","STRIPE_KEY","STRIPE_PUB_KEY","RAZORPAY_KEY","PASSWORD_HINT","PASSPORT","VEHICLE_REG","OPENAI_KEY","GROK_KEY","GOOGLE_API_KEY","BEARER_TOKEN","NPM_TOKEN"];
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
            checkbox.checked = !disabled.has(label);  // Checked = ENABLED
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
      const patternSearch = document.getElementById("patternSearch");
      if (patternSearch) patternSearch.addEventListener("input", e => renderPatterns(e.target.value));
    }

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
          const host = url.host;  // Includes port if present (e.g., localhost:3000)

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

    // Save all settings
    const saveSettingsBtn = document.getElementById("saveSettings");
    if (saveSettingsBtn) {
      saveSettingsBtn.addEventListener("click", async () => {
        const newDisabled = allLabels.filter(label => {
          const cb = document.getElementById(`toggle-${label}`);
          return cb && !cb.checked;
        });

        await chrome.storage.local.set({ disabledPatterns: newDisabled, customSites });

        try {
          await chrome.scripting.unregisterContentScripts();

          const defaultMatches = [
            "*://chatgpt.com/*",
            "*://chat.openai.com/*",
            "*://claude.ai/*",
            "*://grok.x.ai/*",
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

          alert("All settings saved! Refresh pages for site changes.");
        } catch (err) {
          alert("Patterns saved, but sites update failed: " + err.message);
        }
      });
    }
  } catch (err) {
    console.error("🛡️ Popup error:", err);
  }
});