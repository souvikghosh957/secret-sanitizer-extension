// content_script.js - Fixed "Extension context invalidated" error
// Wrapped storage calls in try-catch to handle reloads/invalidation gracefully
// Added fallback: If storage fails, still sanitize/insert + show toast (vault/stats not saved)

console.log("🛡️ Secret Sanitizer content script LOADED successfully!");

// Config
const CONFIG = {
  minEntropyLength: 12,
  entropyThreshold: 4.0,
  vaultTTLMinutes: 15,
  maxVaultEntries: 50
};

// Secret patterns (with previous expansions)
const SECRET_PATTERNS = [
  [/AKIA[0-9A-Z]{16}/gi, "AWS_KEY"],
  [/ASIA[0-9A-Z]{16}/gi, "AWS_TEMP_KEY"],
  [/[ghp|gho|ghu|ghs|ghr]_[A-Za-z0-9]{36}/g, "GITHUB_TOKEN"],
  [/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "JWT"],
  [/(mongodb|postgres|mysql|redis):\/\/[^:\s]+:[^@\s]+@/gi, "DB_CONN"],
  [/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, "CREDIT_CARD"],
  [/[2-9]\d{3}\s?\d{4}\s?\d{4}\s?\d{4}/g, "AADHAAR"],
  [/[A-Z]{5}\d{4}[A-Z]{1}/g, "PAN"],
  [/[6-9]\d{9}/g, "INDIAN_PHONE"],
  [/\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}/gi, "GSTIN"],
  [/[A-Z]{4}0[A-Z0-9]{6}/gi, "IFSC"],
  [/[\w\.-]+@(?:oksbi|okaxis|okhdfcbank|okicici|oksbp|ybl|apl|airtel)/gi, "UPI_ID"],
  [/[\w\.-]+@upi/gi, "UPI_ID_GENERIC"],
  [/[A-Z]{2}[0-9]{2}\s?[0-9]{4}\s?[0-9]{7}/gi, "DRIVING_LICENSE"],
  [/[A-Z]{3}[0-9]{7}/gi, "VOTER_ID"],
  [/\b\d{9,18}\b/g, "BANK_ACCOUNT"],
  [/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "EMAIL"],
  [/sk_live_[A-Za-z0-9]{24}/gi, "STRIPE_KEY"],
  [/pk_live_[A-Za-z0-9]{24}/gi, "STRIPE_PUB_KEY"],
  [/rzp_live_[A-Za-z0-9]{14}/gi, "RAZORPAY_KEY"],
  [/(password|passwd|pwd)[\s:=]+['"]?[A-Za-z0-9!@#$%^&*]{8,}['"]?/gi, "PASSWORD_HINT"]
];

// Entropy calculation
function calculateEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const char of str) freq[char] = (freq[char] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Find high-entropy secrets
function findHighEntropySecrets(text) {
  const candidates = [];
  const words = text.split(/\s+|[\"'`()[\]{},;]/);
  for (let word of words) {
    const clean = word.replace(/[^A-Za-z0-9!@#$%^&*_\-=+]/g, "");
    if (clean.length >= CONFIG.minEntropyLength && calculateEntropy(clean) >= CONFIG.entropyThreshold) {
      const start = text.indexOf(clean);
      if (start !== -1) candidates.push({ secret: clean, start, end: start + clean.length });
    }
  }
  return candidates;
}

// Sanitize text
function sanitizeText(text) {
  let maskedText = text;
  const replacements = [];

  for (const [pattern, label] of SECRET_PATTERNS) {
    const matches = [...maskedText.matchAll(pattern)];
    for (const match of matches) {
      const original = match[0];
      const placeholder = `[${label}_${replacements.length}]`;
      maskedText = maskedText.replace(original, placeholder);
      replacements.push([placeholder, original]);
    }
  }

  const entropySecrets = findHighEntropySecrets(maskedText);
  for (const { secret, start, end } of entropySecrets) {
    const placeholder = `[ENTROPY_${replacements.length}]`;
    maskedText = maskedText.slice(0, start) + placeholder + maskedText.slice(end);
    replacements.push([placeholder, secret]);
  }

  return { maskedText, replacements };
}

// Vault save with try-catch for context invalidation
async function saveToVault(traceId, replacements) {
  const expires = Date.now() + CONFIG.vaultTTLMinutes * 60 * 1000;
  const data = { replacements, expires };

  try {
    const existing = await chrome.storage.local.get(["vault", "stats"]);
    let vault = existing.vault || {};
    let stats = existing.stats || { totalBlocked: 0, todayBlocked: 0, lastDate: null };

    const now = Date.now();
    Object.keys(vault).forEach(key => {
      if (vault[key].expires < now) delete vault[key];
    });

    const today = new Date().toDateString();
    if (stats.lastDate !== today) {
      stats.todayBlocked = 0;
      stats.lastDate = today;
    }
    stats.totalBlocked += replacements.length;
    stats.todayBlocked += replacements.length;

    vault[traceId] = data;

    if (Object.keys(vault).length > CONFIG.maxVaultEntries) {
      const keys = Object.keys(vault).sort((a, b) => vault[a].expires - vault[b].expires);
      delete vault[keys[0]];
    }

    await chrome.storage.local.set({ vault, stats });
    console.log("🛡️ Vault & stats saved successfully");
  } catch (err) {
    if (err.message.includes("Extension context invalidated")) {
      console.warn("🛡️ Extension reloaded - vault not saved (normal during development)");
    } else {
      console.error("🛡️ Storage error:", err);
    }
    // Continue without saving vault/stats - sanitize still works
  }
}

// Toast function (unchanged)
function showToast(message) {
  const toast = document.createElement("div");
  toast.textContent = message;
  Object.assign(toast.style, {
    position: "fixed",
    bottom: "20px",
    right: "20px",
    background: "#28a745",
    color: "white",
    padding: "12px 20px",
    borderRadius: "8px",
    boxShadow: "0 4px 12px rgba(0,0,0,0.2)",
    zIndex: "10000",
    fontFamily: "system-ui, sans-serif",
    fontSize: "14px",
    opacity: "0",
    transition: "opacity 0.4s ease",
    maxWidth: "300px",
    wordWrap: "break-word"
  });

  document.body.appendChild(toast);

  setTimeout(() => { toast.style.opacity = "1"; }, 100);

  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => { toast.remove(); }, 400);
  }, 4000);
}

// Paste handler with error handling
document.addEventListener("paste", async (e) => {
  console.log("🛡️ Paste event detected");

  const clipboardText = (e.clipboardData || window.clipboardData).getData("text");
  if (!clipboardText) return;

  const { maskedText, replacements } = sanitizeText(clipboardText);
  if (replacements.length === 0) return;

  e.preventDefault();
  e.stopImmediatePropagation();

  const traceId = crypto.randomUUID();

  // Save vault async (fire-and-forget with error handling)
  saveToVault(traceId, replacements);

  const insertMaskedText = (text) => {
    try {
      if (document.queryCommandSupported('insertText')) {
        return document.execCommand('insertText', false, text);
      }
    } catch (_) {}

    try {
      const sel = window.getSelection();
      let range = sel.rangeCount > 0 ? sel.getRangeAt(0) : document.createRange();
      range.selectNodeContents(document.activeElement);
      range.collapse(false);
      range.deleteContents();
      range.insertNode(document.createTextNode(text));
      range.collapse(false);
      sel.removeAllRanges();
      sel.addRange(range);
      return true;
    } catch (_) {
      return false;
    }
  };

  if (insertMaskedText(maskedText)) {
    document.activeElement.dispatchEvent(new Event('input', { bubbles: true }));
    console.log(`🛡️ Blocked ${replacements.length} secrets! TraceID: ${traceId}`);
    showToast(`🛡️ Blocked ${replacements.length} secrets!`);
  } else {
    console.error("Insertion failed");
    showToast("⚠️ Sanitizer: Insertion failed!");
  }
}, true);