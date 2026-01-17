// popup.js - Updated: Cleans expired, better recent list, robust unmasking

document.addEventListener("DOMContentLoaded", async () => {
  console.log("🛡️ Secret Sanitizer popup opened");

  let { vault = {}, stats = { totalBlocked: 0, todayBlocked: 0 } } = await chrome.storage.local.get(["vault", "stats"]);

  const now = Date.now();

  // Clean expired vault entries on popup load
  let cleaned = false;
  Object.keys(vault).forEach(key => {
    if (vault[key].expires < now) {
      delete vault[key];
      cleaned = true;
    }
  });
  if (cleaned) {
    await chrome.storage.local.set({ vault });
    console.log("🛡️ Cleaned expired vault entries in popup");
  }

  // Update stats
  document.getElementById("total").textContent = stats.totalBlocked || 0;
  document.getElementById("today").textContent = stats.todayBlocked || 0;

  // Recent sanitizations
  const recentList = document.getElementById("recentList");
  recentList.innerHTML = "";

  const traceIds = Object.keys(vault)
    .sort((a, b) => vault[b].expires - vault[a].expires)  // Newest first
    .slice(0, 10);

  if (traceIds.length === 0) {
    recentList.innerHTML = "<li style='color: #666;'>No recent sanitizations</li>";
  } else {
    traceIds.forEach(id => {
      const entry = vault[id];
      const minsLeft = Math.max(1, Math.round((entry.expires - now) / 60000));
      const li = document.createElement("li");
      li.innerHTML = `<strong>TraceID:</strong> ${id.slice(0, 8)}...<br>
                      <small>${entry.replacements.length} secrets • ${minsLeft} min left</small>`;
      recentList.appendChild(li);
    });
  }

  // Unmask button
  document.getElementById("unmaskBtn").addEventListener("click", () => {
    const inputText = document.getElementById("inputText").value.trim();
    if (!inputText) {
      alert("Paste AI response with placeholders first!");
      return;
    }

    let unmasked = inputText;
    let replacedCount = 0;

    for (const entry of Object.values(vault)) {
      if (entry.expires < now) continue;

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
    if (replacedCount > 0) {
      output.textContent = unmasked;
      output.classList.remove("hidden");
    } else {
      output.textContent = "No matching placeholders found (check if expired or try recent traceID).";
      output.classList.remove("hidden");
    }
  });
});