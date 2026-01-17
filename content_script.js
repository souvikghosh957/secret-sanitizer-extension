// content_script.js - Final Polished Version with All Fixes
// Includes: Expired vault cleanup on save, better stats reset, robust insertion

console.log("🛡️ Secret Sanitizer content script LOADED successfully!");

// Config
const CONFIG = {
  minEntropyLength: 12,
  entropyThreshold: 4.0,
  vaultTTLMinutes: 15,
  maxVaultEntries: 50
};

// Secret patterns (India-first)
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
  [/[\w\.-]+@upi/gi, "UPI_ID_GENERIC"]
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

  // Regex layer
  for (const [pattern, label] of SECRET_PATTERNS) {
    const matches = [...maskedText.matchAll(pattern)];
    for (const match of matches) {
      const original = match[0];
      const placeholder = `[${label}_${replacements.length}]`;
      maskedText = maskedText.replace(original, placeholder);
      replacements.push([placeholder, original]);
    }
  }

  // Entropy layer
  const entropySecrets = findHighEntropySecrets(maskedText);
  for (const { secret, start, end } of entropySecrets) {
    const placeholder = `[ENTROPY_${replacements.length}]`;
    maskedText = maskedText.slice(0, start) + placeholder + maskedText.slice(end);
    replacements.push([placeholder, secret]);
  }

  return { maskedText, replacements };
}

// Vault save with cleanup
async function saveToVault(traceId, replacements) {
  const expires = Date.now() + CONFIG.vaultTTLMinutes * 60 * 1000;
  const data = { replacements, expires };

  const existing = await chrome.storage.local.get(["vault", "stats"]);
  let vault = existing.vault || {};
  let stats = existing.stats || { totalBlocked: 0, todayBlocked: 0, lastDate: null };

  // Clean expired
  const now = Date.now();
  Object.keys(vault).forEach(key => {
    if (vault[key].expires < now) delete vault[key];
  });

  // Update stats
  const today = new Date().toDateString();
  if (stats.lastDate !== today) {
    stats.todayBlocked = 0;
    stats.lastDate = today;
  }
  stats.totalBlocked += replacements.length;
  stats.todayBlocked += replacements.length;

  // Save new
  vault[traceId] = data;

  // Trim excess
  if (Object.keys(vault).length > CONFIG.maxVaultEntries) {
    const keys = Object.keys(vault).sort((a, b) => vault[a].expires - vault[b].expires);
    delete vault[keys[0]];
  }

  await chrome.storage.local.set({ vault, stats });
}

// Paste handler
document.addEventListener("paste", async (e) => {
  console.log("🛡️ Paste event detected");

  const clipboardText = (e.clipboardData || window.clipboardData).getData("text");
  if (!clipboardText) return;

  const { maskedText, replacements } = sanitizeText(clipboardText);
  if (replacements.length === 0) return;

  e.preventDefault();
  e.stopImmediatePropagation();

  const traceId = crypto.randomUUID();
  await saveToVault(traceId, replacements);

  const insertMaskedText = (text) => {
    try {
      if (document.queryCommandSupported('insertText')) {
        return document.execCommand('insertText', false, text);
      }
    } catch (_) {}

    try {
      const sel = window.getSelection();
      let range = sel.rangeCount > 0 ? sel.getRangeAt(0) : document.createRange();
      const activeEl = document.activeElement;
      range.selectNodeContents(activeEl);
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
  } else {
    console.error("Insertion failed");
  }
}, true);