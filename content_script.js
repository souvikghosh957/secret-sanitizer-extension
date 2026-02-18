// content_script.js - Ultra-Optimized Secret Sanitizer
// - Pre-compiled regex patterns
// - Smart caching and early exits
// - Performance metrics
// - Zero-lag paste handling

// Secret Sanitizer content script initialized

// Config
const CONFIG = {
  minEntropyLength: 12,
  entropyThreshold: 4.0,
  vaultTTLMinutes: 15,
  maxVaultEntries: 50,
  cacheSize: 100, // Cache last N text samples
  minTextLength: 10 // Skip processing very short text
};

// Check if extension context is still valid
function isExtensionContextValid() {
  try {
    // Check all required chrome APIs exist and context is valid
    if (!chrome || !chrome.runtime || !chrome.runtime.id) return false;
    if (!chrome.storage || !chrome.storage.local) return false;
    return true;
  } catch (_) {
    return false;
  }
}

// Safe wrapper for chrome.storage.local operations
function safeStorageGet(keys) {
  return new Promise((resolve) => {
    try {
      if (!isExtensionContextValid()) {
        resolve({});
        return;
      }
      chrome.storage.local.get(keys, (result) => {
        if (chrome.runtime.lastError) {
          resolve({});
        } else {
          resolve(result || {});
        }
      });
    } catch (_) {
      resolve({});
    }
  });
}

function safeStorageSet(data) {
  return new Promise((resolve) => {
    try {
      if (!isExtensionContextValid()) {
        resolve();
        return;
      }
      chrome.storage.local.set(data, () => {
        resolve();
      });
    } catch (_) {
      resolve();
    }
  });
}

// Performance cache
const patternCache = new Map();
const encryptionKeyCache = { key: null, timestamp: 0, ttl: 300000 }; // 5 min cache

// Enhanced patterns with comprehensive test secret detection
const ALL_PATTERNS = [
  // AWS Keys (including test/example keys)
  [/\bAKIA[0-9A-Z]{16}\b/gi, "AWS_KEY"],
  [/\bASIA[0-9A-Z]{16}\b/gi, "AWS_TEMP_KEY"],
  [/\b[A-Za-z0-9/+=]{40}\b/g, "AWS_SECRET_KEY"], // AWS Secret Access Key (40 chars base64)
  
  // GitHub Tokens
  [/\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g, "GITHUB_TOKEN"],
  
  // JWT Tokens
  [/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "JWT"],
  
  // Database Connections
  [/(mongodb|postgres|mysql|redis):\/\/[^:\s]+:[^@\s]+@[^\s]+/gi, "DB_CONN"],
  
  // Credit Cards (including test cards)
  [/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g, "CREDIT_CARD"],
  
  // Stripe Keys (live and test)
  [/\bsk_live_[A-Za-z0-9]{24,}\b/gi, "STRIPE_KEY"],
  [/\bsk_test_[A-Za-z0-9]{24,}\b/gi, "STRIPE_TEST_KEY"],
  [/\bpk_live_[A-Za-z0-9]{24,}\b/gi, "STRIPE_PUB_KEY"],
  [/\bpk_test_[A-Za-z0-9]{24,}\b/gi, "STRIPE_TEST_PUB_KEY"],
  
  // Twilio
  [/\bAC[a-z0-9]{32}\b/gi, "TWILIO_SID"],
  [/\b(?:twilio[_\s-]?auth[_\s-]?token|auth[_\s-]?token)[\s:=]+['"]?[A-Za-z0-9]{32,}['"]?/gi, "TWILIO_AUTH_TOKEN"],
  
  // Firebase
  [/\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}\b/g, "FIREBASE_KEY"],
  
  // Razorpay (live and test)
  [/\brzp_live_[A-Za-z0-9]{14,}\b/gi, "RAZORPAY_KEY"],
  [/\brzp_test_[A-Za-z0-9]{14,}\b/gi, "RAZORPAY_TEST_KEY"],
  [/\brzp_test_[A-Za-z0-9]{32,}\b/gi, "RAZORPAY_TEST_SECRET"],
  
  // Paytm patterns
  [/\bpaytm[_\s-]?(?:key|secret|token)[\s:=]+['"]?[A-Za-z0-9]{20,}['"]?/gi, "PAYTM_KEY"],
  [/\b(?:merchant[_\s-]?key|merchant[_\s-]?id)[\s:=]+['"]?[A-Za-z0-9]{20,}['"]?/gi, "PAYTM_MERCHANT"],
  
  // Indian PII
  [/\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, "AADHAAR"],
  [/\b[A-Z]{5}\d{4}[A-Z]{1}\b/g, "PAN"],
  [/\b[6-9]\d{9}\b/g, "INDIAN_PHONE"],
  [/\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}Z[A-Z\d]{1}\b/gi, "GSTIN"],
  [/\b[A-Z]{4}0[A-Z0-9]{6}\b/gi, "IFSC"],
  [/\b[\w\.-]+@(?:oksbi|okaxis|okhdfcbank|okicici|oksbp|ybl|apl|airtel)\b/gi, "UPI_ID"],
  [/\b[\w\.-]+@upi\b/gi, "UPI_ID_GENERIC"],
  // UPI Test IDs
  [/\b(?:success|failure|test)@(?:upi|razorpay|payu)\b/gi, "UPI_TEST_ID"],
  [/\b[\w\.-]+@(?:razorpay|payu|paytm)\b/gi, "PAYMENT_UPI_ID"],
  [/\b[A-Z]{2}[0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{7}\b/gi, "DRIVING_LICENSE"],
  [/\b[A-Z]{3}[0-9]{7}\b/gi, "VOTER_ID"],
  [/\b\d{9,18}\b/g, "BANK_ACCOUNT"],
  [/\b[A-PR-V][1-9]\d{6}\b/gi, "PASSPORT"],
  [/\b[A-Z]{2}\d{1,2}[A-Z]{1,2}\d{4}\b/gi, "VEHICLE_REG"],
  
  // OTP Codes (6-digit codes in suspicious contexts)
  [/(?:otp|pin|code|verification)[\s:=]+['"]?(\d{4,8})['"]?/gi, "OTP_CODE"],
  [/\b(?:enter|your|the)[\s]+(?:otp|pin|code)[\s:]+(\d{4,8})\b/gi, "OTP_CODE"],
  
  // Email (only in suspicious contexts - near passwords/secrets)
  [/(?:password|passwd|pwd|secret|key|token|api)[\s:=]+['"]?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}['"]?/gi, "EMAIL_IN_SECRET"],
  
  // Password hints
  [/(?:password|passwd|pwd)[\s:=]+['"]?[A-Za-z0-9!@#$%^&*]{8,}['"]?/gi, "PASSWORD_HINT"],
  
  // API Keys
  [/\bopenai_[A-Za-z0-9]{48,}\b/gi, "OPENAI_KEY"],
  [/\bgsk_[A-Za-z0-9]{48,}\b/gi, "GROK_KEY"],
  [/\bAIza[0-9A-Za-z\-_]{35,}\b/g, "GOOGLE_API_KEY"],
  [/\b(bearer|token)[\s:]+[A-Za-z0-9\-_.]{20,}\b/gi, "BEARER_TOKEN"],
  [/\bnpm_[A-Za-z0-9]{36,}\b/g, "NPM_TOKEN"],
  
  // API Key format patterns (catches API_KEY="value", API_KEY='value', API_KEY=value)
  [/(?:api[_-]?key|apikey|api_key)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?/gi, "API_KEY_FORMAT"],
  [/(?:secret[_-]?key|secretkey|secret_key)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?/gi, "SECRET_KEY_FORMAT"],
  [/(?:access[_-]?key|accesskey|access_key)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?/gi, "ACCESS_KEY_FORMAT"],
  
  // Private Keys (RSA, EC, etc.)
  [/-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|EC\s+PRIVATE)\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?(?:PRIVATE|EC\s+PRIVATE)\s+KEY-----/gi, "PRIVATE_KEY"],
  [/-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----[\s\S]*?-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/gi, "PGP_PRIVATE_KEY"],
  
  // Generic patterns
  [/\bsk-[A-Za-z0-9]{32,}\b/gi, "GENERIC_SECRET_KEY"],
  // Long random strings in quotes (catches values like "54671we345rrtt412919287edrtwq3")
  [/['"][A-Za-z0-9]{20,}['"]/g, "QUOTED_SECRET"],
  // Standalone long random strings (40+ chars are likely secrets, 64+ very likely)
  [/\b[A-Za-z0-9]{40,}\b/g, "LONG_RANDOM_STRING"],
  // Base64-like strings (common in secrets)
  [/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, "BASE64_SECRET"]
];

let SECRET_PATTERNS = ALL_PATTERNS;
let COMPILED_PATTERNS = [];

// Pre-compile patterns for performance
function compilePatterns(patterns) {
  return patterns.map(([pattern, label]) => ({
    regex: pattern instanceof RegExp ? pattern : new RegExp(pattern.source || pattern, pattern.flags || 'gi'),
    label,
    compiled: true
  }));
}

// Load disabled patterns and compile
(async () => {
  try {
    const { disabledPatterns = [] } = await safeStorageGet("disabledPatterns");
    const disabled = new Set(disabledPatterns);
    SECRET_PATTERNS = ALL_PATTERNS.filter(([, label]) => !disabled.has(label));
    COMPILED_PATTERNS = compilePatterns(SECRET_PATTERNS);
  } catch (_) {
    COMPILED_PATTERNS = compilePatterns(ALL_PATTERNS);
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
  const seen = new Set();
  
  for (let word of words) {
    const clean = word.replace(/[^A-Za-z0-9!@#$%^&*_\-=+]/g, "");
    if (clean.length >= CONFIG.minEntropyLength && 
        calculateEntropy(clean) >= CONFIG.entropyThreshold &&
        !seen.has(clean)) {
      seen.add(clean);
      // Find all occurrences in text
      let start = 0;
      while ((start = text.indexOf(clean, start)) !== -1) {
        // Skip if already masked (contains bracket nearby)
        const context = text.substring(Math.max(0, start - 2), Math.min(text.length, start + clean.length + 2));
        if (!context.includes('[') && !context.includes(']')) {
          candidates.push({ secret: clean, start, end: start + clean.length });
        }
        start += clean.length;
      }
    }
  }
  // Remove overlapping candidates (keep first occurrence)
  return candidates.sort((a, b) => a.start - b.start)
    .filter((cand, idx, arr) => {
      if (idx === 0) return true;
      const prev = arr[idx - 1];
      return cand.start >= prev.end;
    });
}

// Fast range overlap check using sorted array
function hasOverlap(ranges, start, end) {
  // Binary search would be better, but linear is fast enough for small arrays
  for (const r of ranges) {
    if (start < r.end && end > r.start) return true;
  }
  return false;
}

// Optimized sanitize with caching and early exits
function sanitizeText(text) {
  if (!text || text.length < CONFIG.minTextLength) {
    return { maskedText: text, replacements: [] };
  }
  
  // Check cache (simple hash)
  const textHash = text.length + text.charCodeAt(0) + text.charCodeAt(text.length - 1);
  const cacheKey = `${textHash}_${text.length}`;
  if (patternCache.has(cacheKey)) {
    const cached = patternCache.get(cacheKey);
    if (cached.text === text) return cached.result;
  }
  
  let maskedText = text;
  const replacements = [];
  const maskedRanges = []; // Sorted by start position

  // Pattern-based matching (using pre-compiled patterns)
  for (const { regex, label } of COMPILED_PATTERNS) {
    let match;
    while ((match = regex.exec(maskedText)) !== null) {
      const original = match[0];
      const start = match.index;
      const end = start + original.length;
      
      // Fast overlap check
      if (hasOverlap(maskedRanges, start, end)) {
        // Reset lastIndex if global flag to avoid infinite loop
        if (!regex.global) break;
        continue;
      }
      
      const placeholder = `[${label}_${replacements.length}]`;
      maskedText = maskedText.substring(0, start) + placeholder + maskedText.substring(end);
      replacements.push([placeholder, original]);
      
      // Insert range in sorted order
      maskedRanges.push({ start, end: start + placeholder.length });
      maskedRanges.sort((a, b) => a.start - b.start);
      
      // Adjust regex lastIndex for next iteration
      if (regex.global) {
        regex.lastIndex = start + placeholder.length;
      } else {
        break;
      }
    }
    // Reset regex for next pattern
    if (regex.global) regex.lastIndex = 0;
  }

  // Entropy-based detection (only if patterns didn't catch everything)
  if (replacements.length === 0 || maskedText.length > text.length * 0.5) {
    const entropySecrets = findHighEntropySecrets(maskedText);
    for (const { secret, start, end } of entropySecrets) {
      if (!hasOverlap(maskedRanges, start, end)) {
        const placeholder = `[ENTROPY_${replacements.length}]`;
        maskedText = maskedText.slice(0, start) + placeholder + maskedText.slice(end);
        replacements.push([placeholder, secret]);
        maskedRanges.push({ start, end: start + placeholder.length });
        maskedRanges.sort((a, b) => a.start - b.start);
      }
    }
  }

  const result = { maskedText, replacements };

  // Track pattern statistics (async, don't block)
  if (replacements.length > 0) {
    safeStorageGet("patternStats").then(({ patternStats = {} }) => {
      replacements.forEach(([placeholder]) => {
        const match = placeholder.match(/\[(\w+)_/);
        if (match) {
          const patternLabel = match[1];
          patternStats[patternLabel] = (patternStats[patternLabel] || 0) + 1;
        }
      });
      safeStorageSet({ patternStats });
    });
  }
  
  // Cache result (limit cache size)
  if (patternCache.size > CONFIG.cacheSize) {
    const firstKey = patternCache.keys().next().value;
    patternCache.delete(firstKey);
  }
  patternCache.set(cacheKey, { text, result });
  
  return result;
}

// Web Crypto API encryption for vault (AES-GCM) with caching
// Derives key from extension ID for consistent encryption
async function getEncryptionKey() {
  try {
    if (!isExtensionContextValid()) return null;

    const now = Date.now();
    // Use cached key if available and not expired
    if (encryptionKeyCache.key && (now - encryptionKeyCache.timestamp) < encryptionKeyCache.ttl) {
      return encryptionKeyCache.key;
    }

    // Use extension ID as salt (consistent per installation)
    const extensionId = chrome.runtime.id;
    if (!extensionId) return null;
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(extensionId + "secret-sanitizer-vault-key"),
      { name: "PBKDF2" },
      false,
      ["deriveBits", "deriveKey"]
    );
    
    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: new TextEncoder().encode(extensionId),
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    
    // Cache the key
    encryptionKeyCache.key = key;
    encryptionKeyCache.timestamp = now;
    
    return key;
  } catch (err) {
    console.error("Key derivation error:", err);
    return null;
  }
}

async function encryptData(data) {
  try {
    const { useEncryption = true } = await safeStorageGet("useEncryption");
    if (!useEncryption) return { encrypted: false, data };
    
    const key = await getEncryptionKey();
    if (!key) {
      // Fallback to base64 if crypto fails
      const json = JSON.stringify(data);
      return { encrypted: false, data: btoa(new TextEncoder().encode(json).reduce((s, b) => s + String.fromCharCode(b), '')) };
    }
    
    const json = JSON.stringify(data);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(json);
    
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encoded
    );
    
    // Combine IV and encrypted data
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    
    // Convert to base64 for storage (chunked to avoid stack overflow)
    let binary = '';
    const chunkSize = 8192;
    for (let i = 0; i < combined.length; i += chunkSize) {
      binary += String.fromCharCode(...combined.subarray(i, i + chunkSize));
    }
    const base64 = btoa(binary);
    return { encrypted: true, data: base64 };
  } catch (err) {
    console.error("Encryption error:", err);
    // Fallback to base64
    const json = JSON.stringify(data);
    return { encrypted: false, data: btoa(new TextEncoder().encode(json).reduce((s, b) => s + String.fromCharCode(b), '')) };
  }
}

async function decryptData(encryptedData) {
  try {
    const { useEncryption = true } = await safeStorageGet("useEncryption");
    if (!useEncryption) {
      // Handle old format
      if (typeof encryptedData === 'string' && encryptedData.startsWith('[')) {
        return encryptedData;
      }
      if (typeof encryptedData === 'object' && encryptedData.encrypted === false) {
        const decoded = new TextDecoder().decode(Uint8Array.from(atob(encryptedData.data), c => c.charCodeAt(0)));
        return JSON.parse(decoded);
      }
      return encryptedData;
    }
    
    // Handle new encrypted format
    if (typeof encryptedData === 'object' && encryptedData.encrypted === true) {
      const key = await getEncryptionKey();
      if (!key) {
        // Fallback
        const decoded = new TextDecoder().decode(Uint8Array.from(atob(encryptedData.data), c => c.charCodeAt(0)));
        return JSON.parse(decoded);
      }
      
      const combined = Uint8Array.from(atob(encryptedData.data), c => c.charCodeAt(0));
      const iv = combined.slice(0, 12);
      const encrypted = combined.slice(12);
      
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encrypted
      );
      
      const json = new TextDecoder().decode(decrypted);
      return JSON.parse(json);
    }
    
    // Handle old base64 format (backward compatibility)
    if (typeof encryptedData === 'string' && !encryptedData.startsWith('[')) {
      const decoded = new TextDecoder().decode(Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0)));
      return JSON.parse(decoded);
    }
    
    return encryptedData;
  } catch (err) {
    console.error("Decryption error:", err);
    // Try as plain data (backward compatibility)
    return encryptedData;
  }
}

// Vault save - silent on failure with encryption
async function saveToVault(traceId, replacements) {
  if (!isExtensionContextValid()) return;

  const expires = Date.now() + CONFIG.vaultTTLMinutes * 60 * 1000;

  try {
    const { vault = {}, stats = { totalBlocked: 0, todayBlocked: 0, lastDate: null } } = await safeStorageGet(["vault", "stats"]);

    const now = Date.now();
    Object.keys(vault).forEach(key => {
      if (vault[key] && vault[key].expires < now) delete vault[key];
    });

    const today = new Date().toDateString();
    if (stats.lastDate !== today) {
      stats.todayBlocked = 0;
      stats.lastDate = today;
    }
    stats.totalBlocked += replacements.length;
    stats.todayBlocked += replacements.length;

    // Encrypt replacements before storing
    const encryptedResult = await encryptData(replacements);
    vault[traceId] = { 
      replacements: encryptedResult.data, 
      expires, 
      encrypted: encryptedResult.encrypted 
    };

    if (Object.keys(vault).length > CONFIG.maxVaultEntries) {
      const keys = Object.keys(vault).sort((a, b) => (vault[a]?.expires || 0) - (vault[b]?.expires || 0));
      delete vault[keys[0]];
    }

    await safeStorageSet({ vault, stats });
  } catch (_) {
    // Silent - common on Gemini/ChatGPT context reloads
  }
}

// Simple toast for basic messages
function showToast(message, type = "success") {
  if (!document.body) return;
  document.querySelectorAll(".secret-sanitizer-toast").forEach(t => t.remove());

  const toast = document.createElement("div");
  toast.className = "secret-sanitizer-toast";

  const colors = {
    success: { bg: "#10b981", icon: "✓" },
    warning: { bg: "#f59e0b", icon: "⚠" },
    error: { bg: "#ef4444", icon: "✕" },
    info: { bg: "#0ea5e9", icon: "ℹ" }
  };
  const style = colors[type] || colors.success;

  Object.assign(toast.style, {
    position: "fixed",
    bottom: "20px",
    right: "20px",
    background: style.bg,
    color: "white",
    padding: "12px 18px",
    borderRadius: "10px",
    boxShadow: "0 4px 16px rgba(0,0,0,0.2)",
    zIndex: "2147483647",
    fontFamily: "system-ui, -apple-system, sans-serif",
    fontSize: "13px",
    fontWeight: "500",
    opacity: "0",
    transform: "translateY(16px)",
    transition: "all 0.25s ease-out",
    display: "flex",
    alignItems: "center",
    gap: "8px"
  });

  toast.innerHTML = `<span style="font-size:15px">${style.icon}</span><span>${message}</span>`;
  document.body.appendChild(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";
  });

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(16px)";
    setTimeout(() => toast.remove(), 250);
  }, 3000);
}

// Smart toast with secret types and Undo
function showSmartToast(secretTypes, onUndo) {
  if (!document.body) return;
  document.querySelectorAll(".secret-sanitizer-toast").forEach(t => t.remove());

  const toast = document.createElement("div");
  toast.className = "secret-sanitizer-toast";

  // Get unique secret types (without the _0, _1 suffix)
  const types = [...new Set(secretTypes.map(t => t.replace(/_\d+$/, '')))];
  const typeDisplay = types.slice(0, 2).join(", ") + (types.length > 2 ? ` +${types.length - 2}` : "");

  Object.assign(toast.style, {
    position: "fixed",
    bottom: "20px",
    right: "20px",
    background: "#1e293b",
    color: "#f1f5f9",
    padding: "0",
    borderRadius: "12px",
    boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
    zIndex: "2147483647",
    fontFamily: "system-ui, -apple-system, sans-serif",
    fontSize: "13px",
    opacity: "0",
    transform: "translateY(16px)",
    transition: "all 0.25s ease-out",
    overflow: "hidden",
    maxWidth: "340px"
  });

  // Main content
  const content = document.createElement("div");
  Object.assign(content.style, {
    display: "flex",
    alignItems: "center",
    gap: "12px",
    padding: "14px 16px"
  });

  // Shield icon
  const icon = document.createElement("div");
  Object.assign(icon.style, {
    width: "32px",
    height: "32px",
    borderRadius: "8px",
    background: "linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "14px",
    flexShrink: "0"
  });
  icon.textContent = "🛡️";

  // Text content
  const textWrap = document.createElement("div");
  Object.assign(textWrap.style, {
    flex: "1",
    minWidth: "0"
  });

  const title = document.createElement("div");
  Object.assign(title.style, {
    fontWeight: "600",
    fontSize: "13px",
    marginBottom: "2px"
  });
  title.textContent = `Protected ${secretTypes.length} secret${secretTypes.length > 1 ? 's' : ''}`;

  const subtitle = document.createElement("div");
  Object.assign(subtitle.style, {
    fontSize: "11px",
    color: "#94a3b8",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis"
  });
  subtitle.textContent = typeDisplay;

  textWrap.appendChild(title);
  textWrap.appendChild(subtitle);

  content.appendChild(icon);
  content.appendChild(textWrap);

  // Undo button (if callback provided)
  if (onUndo) {
    const undoBtn = document.createElement("button");
    Object.assign(undoBtn.style, {
      background: "rgba(255,255,255,0.1)",
      border: "none",
      color: "#94a3b8",
      padding: "6px 12px",
      borderRadius: "6px",
      fontSize: "12px",
      fontWeight: "500",
      cursor: "pointer",
      transition: "all 0.15s ease",
      flexShrink: "0"
    });
    undoBtn.textContent = "Undo";
    undoBtn.onmouseenter = () => {
      undoBtn.style.background = "rgba(255,255,255,0.15)";
      undoBtn.style.color = "#f1f5f9";
    };
    undoBtn.onmouseleave = () => {
      undoBtn.style.background = "rgba(255,255,255,0.1)";
      undoBtn.style.color = "#94a3b8";
    };
    undoBtn.onclick = (e) => {
      e.stopPropagation();
      onUndo();
      toast.style.opacity = "0";
      toast.style.transform = "translateY(16px)";
      setTimeout(() => {
        toast.remove();
        showToast("Restored original text", "info");
      }, 200);
    };
    content.appendChild(undoBtn);
  }

  toast.appendChild(content);
  document.body.appendChild(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";
  });

  // Auto-dismiss after 5 seconds (longer to allow undo)
  const dismissTimeout = setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(16px)";
    setTimeout(() => toast.remove(), 250);
  }, 5000);

  // Clear timeout if manually dismissed
  toast.addEventListener("click", () => {
    clearTimeout(dismissTimeout);
    toast.style.opacity = "0";
    toast.style.transform = "translateY(16px)";
    setTimeout(() => toast.remove(), 250);
  });
}

// Optimized paste handler with performance tracking
document.addEventListener("paste", (e) => {
  const startTime = performance.now();
  const clipboardText = (e.clipboardData || window.clipboardData).getData("text");
  if (!clipboardText || clipboardText.length < CONFIG.minTextLength) return;

  // Fast path: quick check if text looks like it might contain secrets
  // Includes: API keys, tokens, Indian PII (PAN, Aadhaar, Phone, UPI)
  const quickCheck = /[A-Za-z0-9]{20,}|AKIA|ASIA|ghp_|eyJ|sk_(live|test)|pk_(live|test)|rzp_(live|test)|AC[a-z0-9]{32}|AAAA[A-Z0-9]{7}:|-----BEGIN|API_KEY|SECRET|PRIVATE|OTP|PIN|CODE|password|passwd|pwd|success@|failure@|test@|[A-Z]{5}\d{4}[A-Z]|[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}|[6-9]\d{9}|@(?:ok|ybl|apl|upi|razorpay|payu|paytm|airtel)/i.test(clipboardText);
  if (!quickCheck && clipboardText.length < 50) {
    // Very short text without obvious patterns - skip processing
    return;
  }

  const { maskedText, replacements } = sanitizeText(clipboardText);
  if (replacements.length === 0) return;

  e.preventDefault();
  e.stopImmediatePropagation();

  const traceId = crypto.randomUUID();
  const target = document.activeElement;

  // Async save (don't block UI)
  saveToVault(traceId, replacements).catch(() => {});

  // Track insertion position for undo
  let insertionStart = 0;
  let insertionEnd = 0;

  // Optimized text insertion
  const insertText = (text, element) => {
    if (!element) return false;

    try {
      if (element.isContentEditable || element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
        const start = element.selectionStart || 0;
        const end = element.selectionEnd || 0;
        const value = element.value || element.textContent || '';
        const newValue = value.substring(0, start) + text + value.substring(end);

        insertionStart = start;
        insertionEnd = start + text.length;

        if (element.value !== undefined) {
          element.value = newValue;
          element.setSelectionRange(insertionEnd, insertionEnd);
        } else {
          element.textContent = newValue;
        }

        element.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
      }
    } catch (_) {}

    try {
      if (document.queryCommandSupported('insertText')) {
        document.execCommand('insertText', false, text);
        return true;
      }
    } catch (_) {}

    try {
      const sel = window.getSelection();
      if (sel.rangeCount > 0) {
        const range = sel.getRangeAt(0);
        range.deleteContents();
        range.insertNode(document.createTextNode(text));
        range.collapse(false);
        return true;
      }
    } catch (_) {}

    return false;
  };

  if (insertText(maskedText, target)) {
    // Extract secret types from placeholders (e.g., [OPENAI_KEY_0] -> OPENAI_KEY)
    // Uses same regex pattern as patternStats tracking for consistency
    const secretTypes = replacements.map(([placeholder]) => {
      const match = placeholder.match(/\[(\w+)_/);
      return match ? match[1] : placeholder.replace(/[\[\]]/g, '');
    });

    // Undo function - replaces masked text with original
    const handleUndo = () => {
      try {
        if (target && (target.value !== undefined || target.textContent !== undefined)) {
          const currentValue = target.value !== undefined ? target.value : target.textContent;
          const beforeInsert = currentValue.substring(0, insertionStart);
          const afterInsert = currentValue.substring(insertionEnd);
          const restoredValue = beforeInsert + clipboardText + afterInsert;

          if (target.value !== undefined) {
            target.value = restoredValue;
            target.setSelectionRange(insertionStart + clipboardText.length, insertionStart + clipboardText.length);
          } else {
            target.textContent = restoredValue;
          }
          target.dispatchEvent(new Event('input', { bubbles: true }));
          target.focus();
        }
      } catch (_) {
        showToast("Couldn't restore text", "error");
      }
    };

    showSmartToast(secretTypes, handleUndo);
  } else {
    showToast("Insertion failed! Try pasting again.", "error");
  }
}, true);

// ==================== MILESTONE CELEBRATION ====================

function showMilestoneCelebration(milestone, total) {
  // Remove any existing celebration
  const existing = document.getElementById("ss-milestone-toast");
  if (existing) existing.remove();

  // Position above the secrets-detected toast if it exists
  const secretsToast = document.querySelector('.secret-sanitizer-toast');
  const bottomOffset = secretsToast ? secretsToast.offsetHeight + 32 : 20;

  const toast = document.createElement("div");
  toast.id = "ss-milestone-toast";
  Object.assign(toast.style, {
    position: "fixed",
    bottom: bottomOffset + "px",
    right: "20px",
    background: "linear-gradient(135deg, #1e293b 0%, #0f172a 100%)",
    color: "#f1f5f9",
    padding: "14px 18px",
    borderRadius: "12px",
    boxShadow: "0 8px 32px rgba(0,0,0,0.3), 0 0 0 1px rgba(14,165,233,0.15)",
    zIndex: "2147483647",
    fontFamily: "system-ui, -apple-system, sans-serif",
    display: "flex",
    alignItems: "center",
    gap: "12px",
    opacity: "0",
    transform: "translateY(8px)",
    transition: "all 0.35s cubic-bezier(0.16, 1, 0.3, 1)",
    maxWidth: "320px",
    pointerEvents: "none"
  });

  // Trophy icon with subtle glow
  const icon = document.createElement("div");
  Object.assign(icon.style, {
    width: "36px",
    height: "36px",
    borderRadius: "10px",
    background: "linear-gradient(135deg, rgba(234,179,8,0.15) 0%, rgba(245,158,11,0.1) 100%)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "18px",
    flexShrink: "0"
  });
  icon.textContent = "🏆";

  // Text
  const textWrap = document.createElement("div");
  Object.assign(textWrap.style, { flex: "1", minWidth: "0" });

  const count = document.createElement("div");
  Object.assign(count.style, {
    fontWeight: "700",
    fontSize: "14px",
    letterSpacing: "-0.01em",
    marginBottom: "1px"
  });
  count.innerHTML = `<span style="color:#fbbf24">${milestone.toLocaleString()}</span> <span style="color:#e2e8f0">secrets protected!</span>`;

  const sub = document.createElement("div");
  Object.assign(sub.style, {
    fontSize: "11px",
    color: "#64748b",
    fontWeight: "500"
  });
  sub.textContent = "Milestone reached ✨";

  textWrap.appendChild(count);
  textWrap.appendChild(sub);

  toast.appendChild(icon);
  toast.appendChild(textWrap);
  document.body.appendChild(toast);

  // Animate in
  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";
  });

  // Auto-dismiss after 4 seconds
  setTimeout(() => {
    if (toast.parentNode) {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(8px)";
      setTimeout(() => toast.remove(), 300);
    }
  }, 4000);
}

// ==================== MESSAGE HANDLERS ====================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  try {
    if (request.action === "milestone") {
      showMilestoneCelebration(request.milestone, request.total);
      sendResponse({ success: true });
    } else {
      sendResponse({ success: false, error: "Unknown action" });
    }
  } catch (err) {
    console.error("Message handler error:", err);
    sendResponse({ success: false, error: err.message });
  }
  return true;
});