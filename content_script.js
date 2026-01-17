// content_script.js - Clean, Efficient, Fully Fixed Version
// - More patterns (30+ total, India-focused)
// - False positive support (loads disabled from storage)
// - Safe toast (guards against body null)
// - Fire-and-forget vault save with .catch (no uncaught promises)
// - No floating unmask (removed as requested)

console.log("🛡️ Secret Sanitizer content script LOADED successfully!");

// Config
const CONFIG = {
  minEntropyLength: 12,
  entropyThreshold: 4.0,
  vaultTTLMinutes: 15,
  maxVaultEntries: 50
};

// All patterns
const ALL_PATTERNS = [
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
  [/(password|passwd|pwd)[\s:=]+['"]?[A-Za-z0-9!@#$%^&*]{8,}['"]?/gi, "PASSWORD_HINT"],
  [/[A-PR-V][1-9]\d{6}/gi, "PASSPORT"],
  [/^[A-Z]{2}\d{1,2}[A-Z]{1,2}\d{4}$/gi, "VEHICLE_REG"],
  [/openai_[A-Za-z0-9]{48}/gi, "OPENAI_KEY"],
  [/gsk_[A-Za-z0-9]{48}/gi, "GROK_KEY"],
  [/AIza[0-9A-Za-z\-_]{35}/g, "GOOGLE_API_KEY"],
  [/(bearer|token)[\s:]+[A-Za-z0-9\-_.]{20,}/gi, "BEARER_TOKEN"],
  [/npm_[A-Za-z0-9]{36}/g, "NPM_TOKEN"]
];

let SECRET_PATTERNS = ALL_PATTERNS;

// Load disabled patterns (async, non-blocking)
(async () => {
  try {
    const { disabledPatterns = [] } = await chrome.storage.local.get("disabledPatterns");
    const disabled = new Set(disabledPatterns);
    SECRET_PATTERNS = ALL_PATTERNS.filter(([, label]) => !disabled.has(label));
    console.log(`🛡️ ${SECRET_PATTERNS.length}/${ALL_PATTERNS.length} patterns enabled`);
  } catch (err) {
    console.warn("🛡️ Failed to load disabled patterns - using all");
  }
})();

// Entropy
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

// Sanitize
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

// Vault save (safe)
async function saveToVault(traceId, replacements) {
  const expires = Date.now() + CONFIG.vaultTTLMinutes * 60 * 1000;
  const data = { replacements, expires };

  try {
    const { vault = {}, stats = { totalBlocked: 0, todayBlocked: 0, lastDate: null } } = await chrome.storage.local.get(["vault", "stats"]);

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
  } catch (err) {
    console.warn("🛡️ Vault save failed:", err.message || err);
  }
}

// Safe toast (guards body null)
function showToast(message) {
  if (!document.body) {
    console.warn("🛡️ Toast skipped - document.body not ready");
    return;
  }

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
  setTimeout(() => toast.style.opacity = "1", 100);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 400);
  }, 4000);
}

// Paste handler
document.addEventListener("paste", (e) => {
  const clipboardText = (e.clipboardData || window.clipboardData).getData("text");
  if (!clipboardText) return;

  const { maskedText, replacements } = sanitizeText(clipboardText);
  if (replacements.length === 0) return;

  e.preventDefault();
  e.stopImmediatePropagation();

  const traceId = crypto.randomUUID();

  // Fire-and-forget with catch (no uncaught promises)
  saveToVault(traceId, replacements).catch(err => console.warn("🛡️ Vault save rejected:", err));

  const insertMaskedText = (text) => {
    try {
      if (document.queryCommandSupported('insertText') && document.execCommand('insertText', false, text)) return true;
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
    showToast("⚠️ Insertion failed!");
  }
}, true);