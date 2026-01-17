// popup.js - Updated: Added null checks for all elements to prevent crashes
// Robust against missing elements (e.g., if HTML is incomplete)

document.addEventListener("DOMContentLoaded", async () => {
  console.log("🛡️ Secret Sanitizer popup opened");

  try {
    const { vault = {}, stats = { totalBlocked: 0, todayBlocked: 0 }, disabledPatterns = [] } = await chrome.storage.local.get(["vault", "stats", "disabledPatterns"]);
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
    if (cleaned) {
      await chrome.storage.local.set({ vault }).catch(err => console.warn("Failed to save cleaned vault:", err));
    }

    // Stats (with null guards)
    const totalEl = document.getElementById("total");
    const todayEl = document.getElementById("today");
    if (totalEl) totalEl.textContent = stats.totalBlocked || 0;
    if (todayEl) todayEl.textContent = stats.todayBlocked || 0;

    // Recent sanitizations
    const recentList = document.getElementById("recentList");
    if (recentList) {
      recentList.innerHTML = "";
      const traceIds = Object.keys(vault)
        .sort((a, b) => (vault[b]?.expires || 0) - (vault[a]?.expires || 0))
        .slice(0, 10);

      if (traceIds.length === 0) {
        recentList.innerHTML = "<li style='color: #666;'>No recent sanitizations</li>";
      } else {
        traceIds.forEach(id => {
          const entry = vault[id];
          if (!entry) return;
          const minsLeft = Math.max(1, Math.round((entry.expires - now) / 60000));
          const li = document.createElement("li");
          li.innerHTML = `<strong>TraceID:</strong> ${id.slice(0, 8)}...<br>
                          <small>${entry.replacements.length} secrets • ${minsLeft} min left</small>`;
          recentList.appendChild(li);
        });
      }
    } else {
      console.warn("recentList element not found");
    }

    // Settings toggles
    const togglesDiv = document.getElementById("patternToggles");
    const saveBtn = document.getElementById("saveSettings");

    if (togglesDiv && saveBtn) {
      const toggleLabels = ["EMAIL", "BANK_ACCOUNT", "PASSWORD_HINT", "BEARER_TOKEN", "VEHICLE_REG"];

      toggleLabels.forEach(label => {
        const div = document.createElement("div");
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked = !disabled.has(label);
        checkbox.id = `toggle-${label}`;

        const lbl = document.createElement("label");
        lbl.htmlFor = checkbox.id;
        lbl.textContent = ` Disable ${label}`;

        div.appendChild(checkbox);
        div.appendChild(lbl);
        togglesDiv.appendChild(div);
      });

      saveBtn.addEventListener("click", async () => {
        const newDisabled = toggleLabels.filter(label => {
          const cb = document.getElementById(`toggle-${label}`);
          return cb && !cb.checked;
        });
        try {
          await chrome.storage.local.set({ disabledPatterns: newDisabled });
          alert("Settings saved! Reload the extension to apply changes.");
        } catch (err) {
          alert("Failed to save settings: " + err.message);
        }
      });
    } else {
      console.warn("Settings elements not found (patternToggles or saveSettings missing)");
    }

    // Unmask button
    const unmaskBtn = document.getElementById("unmaskBtn");
    const inputText = document.getElementById("inputText");
    const output = document.getElementById("output");

    if (unmaskBtn && inputText && output) {
      unmaskBtn.addEventListener("click", () => {
        const text = inputText.value.trim();
        if (!text) {
          alert("Paste AI response with placeholders first!");
          return;
        }

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

        output.textContent = replacedCount > 0 ? unmasked : "No matching placeholders found.";
        output.classList.remove("hidden");
      });
    } else {
      console.warn("Unmask elements not found");
    }
  } catch (err) {
    console.error("🛡️ Popup error:", err);
  }
});