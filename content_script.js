// Config
const CONFIG = {
  minEntropyLength: 12,
  entropyThreshold: 4.2,
  vaultTTLMinutes: 15,
  maxVaultEntries: 50,
  cacheSize: 100, // Cache last N text samples
  minTextLength: 10, // Skip processing very short text
  maxMatchesPerScan: 100, // Cap matches to avoid bloat on large pastes
  largePasteThreshold: 5000 // 5KB — skip generic patterns + entropy above this
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
        if (chrome.runtime.lastError) {
          console.warn('Storage write failed:', chrome.runtime.lastError.message);
        }
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

// Serial queue for storage writes to prevent read-modify-write races
const storageQueue = {
  _chain: Promise.resolve(),
  run(fn) {
    this._chain = this._chain.then(fn, fn);
    return this._chain;
  }
};

// Patterns are defined in patterns.js (shared with popup.js to prevent drift)
const ALL_PATTERNS = SHARED_PATTERNS;
let SECRET_PATTERNS = ALL_PATTERNS;

// Generic fallback pattern labels — slow on large text, skipped for pastes > largePasteThreshold
const TIER2_LABELS = new Set(["QUOTED_SECRET", "LONG_RANDOM_STRING", "BASE64_SECRET"]);

// Broad patterns without distinctive prefixes — skipped on large text (>5KB) to avoid
// full-string regex scans on code/HTML where they produce mostly false positives.
const LARGE_TEXT_SKIP_LABELS = new Set([
  "CREDIT_CARD", "AADHAAR", "PAN", "GSTIN", "IFSC",
  "DRIVING_LICENSE", "TELEGRAM_BOT_TOKEN", "TWILIO_SID",
]);

// Literal guard strings (lowercase) — checked via fast includes() before running regex.
// If the guard substring isn't in the text, the regex is skipped entirely.
// Patterns without a guard entry always run (unless skipped by LARGE_TEXT_SKIP_LABELS).
const PATTERN_GUARDS = {
  AWS_KEY: 'akia', AWS_TEMP_KEY: 'asia',
  AZURE_SECRET: 'azure', GOOGLE_API_KEY: 'aiza',
  GITHUB_TOKEN: 'gh', GITHUB_FINE_PAT: 'github_pat_',
  GITLAB_TOKEN: 'glpat-', GITLAB_TRIGGER_TOKEN: 'glptt-',
  JWT: 'eyj', DB_CONN: '://',
  STRIPE_KEY: 'sk_live_', STRIPE_TEST_KEY: 'sk_test_',
  STRIPE_PUB_KEY: 'pk_live_', STRIPE_TEST_PUB_KEY: 'pk_test_',
  SQUARE_ACCESS_TOKEN: 'sq0atp-', SQUARE_SECRET: 'sq0csp-',
  RAZORPAY_KEY: 'rzp_', RAZORPAY_TEST_KEY: 'rzp_',
  PAYTM_KEY: 'paytm', PAYTM_MERCHANT: 'merchant',
  TWILIO_AUTH_TOKEN: 'twilio', SLACK_TOKEN: 'xox',
  DISCORD_WEBHOOK: 'discord', SENDGRID_KEY: 'sg.',
  MAILGUN_KEY: 'mailgun',
  ANTHROPIC_KEY: 'sk-ant-', OPENAI_KEY: 'sk-',
  GROQ_KEY: 'gsk_', HUGGINGFACE_TOKEN: 'hf_',
  FIREBASE_KEY: 'aaaa', HEROKU_API_KEY: 'heroku',
  DIGITALOCEAN_TOKEN: 'dop_v1_', DIGITALOCEAN_REFRESH: 'doctl-',
  SUPABASE_TOKEN: 'sbp_', CLOUDFLARE_TOKEN: 'cloudflare',
  VERCEL_TOKEN: 'vc', DATADOG_KEY: 'datadog', SHOPIFY_TOKEN: 'shp',
  NPM_TOKEN: 'npm_', PYPI_TOKEN: 'pypi-',
  PRIVATE_KEY: '-----begin', SSH_PRIVATE_KEY: '-----begin', PGP_PRIVATE_KEY: '-----begin',
  UPI_ID: '@', UPI_ID_GENERIC: '@upi', UPI_TEST_ID: '@', PAYMENT_UPI_ID: '@',
  VOTER_ID: 'voter', PASSPORT: 'passport', VEHICLE_REG: 'vehicle',
  API_KEY_FORMAT: 'api', ACCESS_KEY_FORMAT: 'access',
  SECRET_KEY_FORMAT: 'secret',
};

let COMPILED_PATTERNS = compilePatterns(ALL_PATTERNS);

// Pre-compile patterns — always create NEW RegExp instances to avoid shared lastIndex state
// Returns { tier1: [...specific], tier2: [...generic] } for tiered execution
// Attaches a lowercase guard string (if available) for fast pre-filtering
// Marks broad patterns with skipOnLargeText for large-paste optimization
function compilePatterns(patterns) {
  const tier1 = [];
  const tier2 = [];
  for (const [pattern, label] of patterns) {
    const guard = PATTERN_GUARDS[label] || null;
    const skipOnLargeText = LARGE_TEXT_SKIP_LABELS.has(label);
    const compiled = { regex: new RegExp(pattern.source, pattern.flags), label, guard, skipOnLargeText };
    if (TIER2_LABELS.has(label)) {
      tier2.push(compiled);
    } else {
      tier1.push(compiled);
    }
  }
  return { tier1, tier2 };
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

// Helper: run a list of compiled patterns against text, pushing matches into allMatches.
// textLower is the pre-lowercased text for fast guard checks.
// isLargePaste skips broad patterns that produce noise on code/HTML.
// Returns true if the match cap was hit (early exit signal).
function runPatterns(patterns, text, textLower, allMatches, isLargePaste) {
  for (const { regex, label, guard, skipOnLargeText } of patterns) {
    // Skip broad unanchored patterns on large text (false-positive heavy on code/HTML)
    if (isLargePaste && skipOnLargeText) continue;
    // Fast pre-filter: skip regex entirely if required literal isn't in text
    if (guard && !textLower.includes(guard)) continue;

    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const original = match[0];
      const start = match.index;
      const end = start + original.length;

      // Guard against zero-length matches to prevent infinite loops
      if (original.length === 0) {
        regex.lastIndex = start + 1;
        continue;
      }

      allMatches.push({ start, end, label, original });

      // Early exit if we've hit the match cap
      if (allMatches.length >= CONFIG.maxMatchesPerScan) {
        regex.lastIndex = 0;
        return true;
      }

      if (!regex.global) break;
    }
    regex.lastIndex = 0;
  }
  return false;
}

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
  // Match contiguous runs of non-whitespace, non-delimiter characters
  const wordRegex = /[^\s"'`()[\]{},;]+/g;
  const seen = new Set();
  let wordMatch;

  while ((wordMatch = wordRegex.exec(text)) !== null) {
    const word = wordMatch[0];
    const wordStart = wordMatch.index;
    // Use the raw word for entropy check (strip only leading/trailing punctuation)
    const trimmed = word.replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, "");
    const trimOffset = word.indexOf(trimmed);
    if (trimmed.length < CONFIG.minEntropyLength) continue;

    // NEW: Skip URL-like strings to avoid false positives on GitHub links, etc.
    if (word.startsWith('http') && word.includes('://')) continue;

    // Calculate entropy on alphanumeric-only content
    const alphanumOnly = trimmed.replace(/[^A-Za-z0-9]/g, "");
    if (alphanumOnly.length < CONFIG.minEntropyLength) continue;
    if (calculateEntropy(alphanumOnly) < CONFIG.entropyThreshold) continue;
    if (seen.has(trimmed)) continue;
    seen.add(trimmed);

    // Use the actual position in text (no indexOf — exact from regex match)
    const start = wordStart + trimOffset;
    const end = start + trimmed.length;

    // Skip if near brackets (likely already a placeholder)
    const ctxStart = Math.max(0, start - 2);
    const ctxEnd = Math.min(text.length, end + 2);
    const context = text.substring(ctxStart, ctxEnd);
    if (context.includes('[') || context.includes(']')) continue;

    candidates.push({ secret: trimmed, start, end });
  }

  return candidates;
}

// FNV-1a hash for cache keys — fast, low-collision string hash
// For large strings (>2KB), sample first+last 512 chars + length for speed.
// Cache hits are still verified by full text === comparison.
function fnv1aHash(str) {
  let hash = 0x811c9dc5; // FNV offset basis
  let source = str;
  if (str.length > 2048) {
    source = str.slice(0, 512) + str.slice(-512) + str.length;
  }
  for (let i = 0; i < source.length; i++) {
    hash ^= source.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0; // FNV prime, keep as uint32
  }
  return hash.toString(36);
}

// Optimized sanitize with caching and early exits
function sanitizeText(text) {
  if (!text || text.length < CONFIG.minTextLength) {
    return { maskedText: text, replacements: [] };
  }

  // Check cache (FNV-1a inspired hash for better distribution)
  const cacheKey = fnv1aHash(text);
  if (patternCache.has(cacheKey)) {
    const cached = patternCache.get(cacheKey);
    if (cached.text === text) {
      // Move to end for LRU eviction (delete + re-insert)
      patternCache.delete(cacheKey);
      patternCache.set(cacheKey, cached);
      return cached.result;
    }
  }

  // Phase 1: Collect ALL matches in original-text coordinates (no mutations)
  const allMatches = []; // { start, end, label, original }
  const isLargePaste = text.length > CONFIG.largePasteThreshold;
  const textLower = text.toLowerCase(); // one-time cost for fast guard checks

  // Tier 1: specific prefixed patterns — guards + skipOnLargeText filter most out for big pastes
  let capped = runPatterns(COMPILED_PATTERNS.tier1, text, textLower, allMatches, isLargePaste);

  // Tier 2: generic fallbacks (QUOTED_SECRET, LONG_RANDOM_STRING, BASE64_SECRET)
  // Skip entirely on large pastes — these are slow unanchored scans that produce noise on code/HTML
  if (!capped && !isLargePaste) {
    capped = runPatterns(COMPILED_PATTERNS.tier2, text, textLower, allMatches, false);
  }

  // Entropy-based detection on original text (fallback for secrets without known prefixes)
  // Skip when: large paste, match cap hit, or patterns already found enough (≥5)
  if (!capped && !isLargePaste && allMatches.length < 5) {
    const entropySecrets = findHighEntropySecrets(text);
    for (const { secret, start, end } of entropySecrets) {
      allMatches.push({ start, end, label: 'ENTROPY', original: secret });
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

  if (filtered.length === 0) {
    const result = { maskedText: text, replacements: [] };
    // Cache clean results too — avoids re-scanning the same large text
    if (patternCache.size > CONFIG.cacheSize) {
      const firstKey = patternCache.keys().next().value;
      patternCache.delete(firstKey);
    }
    patternCache.set(cacheKey, { text, result });
    return result;
  }

  // Phase 3: Build masked text in one pass (left to right), assign placeholders
  const replacements = [];
  const parts = [];
  let cursor = 0;
  for (const m of filtered) {
    if (m.start > cursor) {
      parts.push(text.substring(cursor, m.start));
    }
    const placeholder = `[${m.label}_${replacements.length}]`;
    parts.push(placeholder);
    replacements.push([placeholder, m.original]);
    cursor = m.end;
  }
  if (cursor < text.length) {
    parts.push(text.substring(cursor));
  }
  const maskedText = parts.join('');

  const result = { maskedText, replacements };

  // Track pattern statistics (serialized to prevent lost updates)
  if (replacements.length > 0) {
    storageQueue.run(async () => {
      const { patternStats = {} } = await safeStorageGet("patternStats");
      replacements.forEach(([placeholder]) => {
        const match = placeholder.match(/\[(\w+)_/);
        if (match) {
          const patternLabel = match[1];
          patternStats[patternLabel] = (patternStats[patternLabel] || 0) + 1;
        }
      });
      await safeStorageSet({ patternStats });
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

// Vault save - serialized to prevent read-modify-write races
async function saveToVault(traceId, replacements) {
  if (!isExtensionContextValid()) return;

  return storageQueue.run(async () => {
    try {
      const expires = Date.now() + CONFIG.vaultTTLMinutes * 60 * 1000;
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
  });
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

  const iconSpan = document.createElement("span");
  iconSpan.style.fontSize = "15px";
  iconSpan.textContent = style.icon;
  const msgSpan = document.createElement("span");
  msgSpan.textContent = message;
  toast.appendChild(iconSpan);
  toast.appendChild(msgSpan);
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

// Subtle "clean" toast - confirms extension is active even when no secrets found
function showCleanToast() {
  if (!document.body) return;
  // Don't spam - throttle to once per 30 seconds
  if (showCleanToast._lastShown && Date.now() - showCleanToast._lastShown < 30000) return;
  showCleanToast._lastShown = Date.now();

  document.querySelectorAll(".secret-sanitizer-clean-toast").forEach(t => t.remove());

  const toast = document.createElement("div");
  toast.className = "secret-sanitizer-clean-toast";

  Object.assign(toast.style, {
    position: "fixed",
    bottom: "20px",
    right: "20px",
    background: "rgba(30, 41, 59, 0.85)",
    backdropFilter: "blur(8px)",
    color: "#94a3b8",
    padding: "10px 16px",
    borderRadius: "10px",
    boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
    zIndex: "2147483647",
    fontFamily: "system-ui, -apple-system, sans-serif",
    fontSize: "12px",
    fontWeight: "500",
    opacity: "0",
    transform: "translateY(12px)",
    transition: "all 0.25s ease-out",
    display: "flex",
    alignItems: "center",
    gap: "8px",
    pointerEvents: "none"
  });

  const checkSpan = document.createElement("span");
  checkSpan.style.cssText = "color:#34d399;font-size:13px";
  checkSpan.textContent = "\u2713";
  const cleanMsg = document.createElement("span");
  cleanMsg.textContent = "Scanned \u2014 no secrets found";
  toast.appendChild(checkSpan);
  toast.appendChild(cleanMsg);
  document.body.appendChild(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";
  });

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(12px)";
    setTimeout(() => toast.remove(), 250);
  }, 1500);
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

  // Auto-dismiss after 5 seconds (longer to allow undo)
  // Declared before undo button so the onclick closure can reference it
  let dismissTimeout;

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
    // Prevent button from stealing focus away from the editor
    undoBtn.addEventListener("mousedown", (e) => e.preventDefault());
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
      clearTimeout(dismissTimeout);
      const success = onUndo();
      toast.style.opacity = "0";
      toast.style.transform = "translateY(16px)";
      setTimeout(() => {
        toast.remove();
        showToast(success !== false ? "Restored original text" : "Couldn't restore text", success !== false ? "info" : "error");
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

  dismissTimeout = setTimeout(() => {
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
// Use window capture phase to fire BEFORE any site handlers on document
window.addEventListener("paste", (e) => {
  const clipboardText = e.clipboardData?.getData("text");
  if (!clipboardText || clipboardText.length < CONFIG.minTextLength) return;

  // Fast path: quick check if text looks like it might contain secrets
  const quickCheck = /[A-Za-z0-9]{20,}|AKIA|ASIA|ghp_|github_pat_|glpat-|eyJ|sk_(live|test)|pk_(live|test)|sk-proj-|sk-ant-|rzp_(live|test)|AC[a-z0-9]{32}|AAAA[A-Z0-9]{7}:|xox[bpsare]-|SG\.|hf_|gsk_|shp(?:at|ca|pa|ss|ua)_|dop_v1_|sbp_|npm_|sq0|vc[pcirka]_|-----BEGIN|API_KEY|SECRET|PRIVATE|OTP|PIN|CODE|password|passwd|pwd|bearer|token[\s:=]|success@|failure@|test@|discord(?:app)?\.com\/api\/webhooks|[A-Z]{5}\d{4}[A-Z]|[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}|\+91|phone|mobile|voter|passport|vehicle|@(?:ok|ybl|apl|upi|razorpay|payu|paytm|airtel)|mongodb:|postgres:|mysql:|redis:|amqp:/i.test(clipboardText);
  if (!quickCheck && clipboardText.length < 200) {
    // Short/medium text without obvious patterns - skip processing
    return;
  }

  const { maskedText, replacements } = sanitizeText(clipboardText);
  if (replacements.length === 0) {
    showCleanToast();
    return;
  }

  e.preventDefault();
  e.stopImmediatePropagation();

  const traceId = crypto.randomUUID();
  const target = document.activeElement;

  // Async save (don't block UI)
  saveToVault(traceId, replacements).catch(() => {
    showToast("Could not save to vault — undo unavailable", "warning");
  });

  let inserted = false;

  if (target && target.isContentEditable) {
    // ContentEditable (ChatGPT/Lexical, Claude/ProseMirror, Gemini):
    // execCommand('insertText') integrates with the editor's undo stack.
    try {
      inserted = document.execCommand('insertText', false, maskedText);
    } catch (_) {}

    // Fallback: Selection API (no undo stack integration)
    if (!inserted) {
      try {
        const sel = window.getSelection();
        if (sel.rangeCount > 0) {
          const range = sel.getRangeAt(0);
          range.deleteContents();
          range.insertNode(document.createTextNode(maskedText));
          range.collapse(false);
          target.dispatchEvent(new Event('input', { bubbles: true }));
          inserted = true;
        }
      } catch (_) {}
    }
  } else if (target && (target.tagName === 'TEXTAREA' || target.tagName === 'INPUT')) {
    // Textarea / Input elements
    try {
      const start = target.selectionStart || 0;
      const end = target.selectionEnd || 0;
      const value = target.value || '';
      const newValue = value.substring(0, start) + maskedText + value.substring(end);

      // Use native setter for React/framework compatibility
      const nativeSetter = Object.getOwnPropertyDescriptor(
        Object.getPrototypeOf(target), 'value'
      )?.set;
      if (nativeSetter) {
        nativeSetter.call(target, newValue);
      } else {
        target.value = newValue;
      }
      const cursorPos = start + maskedText.length;
      target.setSelectionRange(cursorPos, cursorPos);
      target.dispatchEvent(new Event('input', { bubbles: true }));
      target.dispatchEvent(new Event('change', { bubbles: true }));
      inserted = true;
    } catch (_) {}
  }

  if (inserted) {
    // Extract secret types from placeholders (e.g., [OPENAI_KEY_0] -> OPENAI_KEY)
    const secretTypes = replacements.map(([placeholder]) => {
      const match = placeholder.match(/\[(\w+)_/);
      return match ? match[1] : placeholder.replace(/[\[\]]/g, '');
    });

    // Undo: replace each placeholder with its original secret individually.
    // This is more robust than replacing the entire maskedText at once, because
    // rich text editors (Lexical, ProseMirror) often split/reformat inserted text.
    const handleUndo = () => {
      try {
        if (target.isContentEditable) {
          target.focus();
          let restored = 0;

          // Replace each placeholder individually in reverse order (last first)
          // so earlier positions aren't shifted by earlier replacements
          for (let i = replacements.length - 1; i >= 0; i--) {
            const [placeholder, original] = replacements[i];

            // Walk text nodes fresh each time (DOM changes after each replacement)
            const walker = document.createTreeWalker(target, NodeFilter.SHOW_TEXT);
            let node;
            while ((node = walker.nextNode())) {
              const idx = node.textContent.indexOf(placeholder);
              if (idx !== -1) {
                // Select just this placeholder and replace it
                const range = document.createRange();
                range.setStart(node, idx);
                range.setEnd(node, idx + placeholder.length);
                const sel = window.getSelection();
                sel.removeAllRanges();
                sel.addRange(range);
                document.execCommand('insertText', false, original);
                restored++;
                break;
              }
            }
          }

          // If no individual placeholders found, try full-text fallback
          if (restored === 0) {
            document.execCommand('undo');
          }
          target.focus();
          return restored > 0;
        } else if (target.value !== undefined) {
          target.focus();

          // Replace each placeholder individually in the value
          let currentValue = target.value;
          let restored = 0;

          for (const [placeholder, original] of replacements) {
            const idx = currentValue.indexOf(placeholder);
            if (idx !== -1) {
              currentValue = currentValue.substring(0, idx) + original + currentValue.substring(idx + placeholder.length);
              restored++;
            }
          }

          if (restored > 0) {
            // Use native setter for React/framework compatibility
            const nativeSetter = Object.getOwnPropertyDescriptor(
              Object.getPrototypeOf(target), 'value'
            )?.set;
            if (nativeSetter) {
              nativeSetter.call(target, currentValue);
            } else {
              target.value = currentValue;
            }
          } else {
            // Full-text fallback: replace entire maskedText block
            const idx = currentValue.indexOf(maskedText);
            if (idx !== -1) {
              target.value = currentValue.substring(0, idx) + clipboardText + currentValue.substring(idx + maskedText.length);
            }
          }
          target.dispatchEvent(new Event('input', { bubbles: true }));
          target.dispatchEvent(new Event('change', { bubbles: true }));
          return restored > 0;
        }
        return false;
      } catch (_) {
        return false;
      }
    };

    showSmartToast(secretTypes, handleUndo);

    // Check if we should prompt for a review (delayed to not overlap)
    setTimeout(() => checkReviewPrompt(), 6000);
  } else {
    showToast("Insertion failed! Try pasting again.", "error");
  }
}, true);

// ==================== REVIEW PROMPT ====================

const REVIEW_MILESTONES = [10, 50, 100, 500, 1000, 5000, 10000];

async function checkReviewPrompt() {
  try {
    const { stats = {}, reviewLastShownAt = 0 } = await safeStorageGet(["stats", "reviewLastShownAt"]);
    const total = stats.totalBlocked || 0;

    // Find the highest milestone the user has crossed
    let currentMilestone = 0;
    for (const m of REVIEW_MILESTONES) {
      if (total >= m) currentMilestone = m;
    }

    // Don't show if below first milestone or already shown at this milestone
    if (currentMilestone === 0) return;
    if (reviewLastShownAt >= currentMilestone) return;

    // Mark this milestone as shown before displaying
    await safeStorageSet({ reviewLastShownAt: currentMilestone });
    showReviewToast(currentMilestone, total);
  } catch (_) {}
}

function showReviewToast(milestone, total) {
  if (!document.body) return;
  document.querySelectorAll(".secret-sanitizer-review-toast").forEach(t => t.remove());

  // Inject keyframes once
  if (!document.getElementById("ss-review-keyframes")) {
    const style = document.createElement("style");
    style.id = "ss-review-keyframes";
    style.textContent = `
      @keyframes ss-review-shimmer {
        0% { background-position: -200% 0; }
        100% { background-position: 200% 0; }
      }
      @keyframes ss-review-glow {
        0%, 100% { box-shadow: 0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(251,191,36,0.1), 0 0 20px rgba(251,191,36,0.05); }
        50% { box-shadow: 0 8px 40px rgba(0,0,0,0.5), 0 0 0 1px rgba(251,191,36,0.2), 0 0 30px rgba(251,191,36,0.1); }
      }
      @keyframes ss-star-spin {
        0% { transform: rotate(0deg) scale(1); }
        25% { transform: rotate(10deg) scale(1.1); }
        50% { transform: rotate(0deg) scale(1); }
        75% { transform: rotate(-10deg) scale(1.05); }
        100% { transform: rotate(0deg) scale(1); }
      }
`;
    document.head.appendChild(style);
  }

  const toast = document.createElement("div");
  toast.className = "secret-sanitizer-review-toast";

  Object.assign(toast.style, {
    position: "fixed",
    bottom: "20px",
    right: "20px",
    background: "linear-gradient(145deg, #0f172a 0%, #1e293b 50%, #0f172a 100%)",
    color: "#f1f5f9",
    padding: "0",
    borderRadius: "16px",
    boxShadow: "0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(251,191,36,0.1), 0 0 20px rgba(251,191,36,0.05)",
    animation: "ss-review-glow 3s ease-in-out infinite",
    zIndex: "2147483647",
    fontFamily: "system-ui, -apple-system, sans-serif",
    fontSize: "13px",
    opacity: "0",
    transform: "translateY(20px) scale(0.95)",
    transition: "all 0.4s cubic-bezier(0.16, 1, 0.3, 1)",
    overflow: "hidden",
    maxWidth: "340px",
    backdropFilter: "blur(16px)"
  });

  // Top shimmer border
  const shimmer = document.createElement("div");
  Object.assign(shimmer.style, {
    height: "2px",
    background: "linear-gradient(90deg, transparent, rgba(251,191,36,0.6), rgba(14,165,233,0.6), transparent)",
    backgroundSize: "200% 100%",
    animation: "ss-review-shimmer 3s linear infinite"
  });

  const content = document.createElement("div");
  Object.assign(content.style, {
    padding: "16px 18px",
    display: "flex",
    flexDirection: "column",
    gap: "12px"
  });

  // Header row with icon + text
  const header = document.createElement("div");
  Object.assign(header.style, {
    display: "flex",
    alignItems: "center",
    gap: "12px"
  });

  const icon = document.createElement("div");
  Object.assign(icon.style, {
    width: "38px",
    height: "38px",
    borderRadius: "12px",
    background: "linear-gradient(135deg, rgba(251,191,36,0.15) 0%, rgba(245,158,11,0.08) 100%)",
    border: "1px solid rgba(251,191,36,0.15)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "18px",
    flexShrink: "0",
    animation: "ss-star-spin 3s ease-in-out infinite"
  });
  icon.textContent = "\u2B50";

  const textWrap = document.createElement("div");
  Object.assign(textWrap.style, { flex: "1", minWidth: "0" });

  const title = document.createElement("div");
  Object.assign(title.style, {
    fontWeight: "700",
    fontSize: "14px",
    letterSpacing: "-0.01em",
    marginBottom: "2px"
  });

  const milestoneText = milestone >= 1000
    ? (milestone / 1000).toLocaleString() + "K"
    : milestone.toLocaleString();
  const milestoneSpan = document.createElement("span");
  milestoneSpan.style.cssText = "background:linear-gradient(135deg,#fbbf24,#f59e0b);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text";
  milestoneSpan.textContent = milestoneText;
  title.appendChild(milestoneSpan);
  title.appendChild(document.createTextNode(" secrets protected"));

  const sub = document.createElement("div");
  Object.assign(sub.style, {
    fontSize: "11px",
    color: "#64748b",
    fontWeight: "500",
    lineHeight: "1.4"
  });
  sub.textContent = milestone >= 100
    ? "Trusted with " + total.toLocaleString() + " secrets. Help others stay safe."
    : "Loving it? A quick rating goes a long way.";

  textWrap.appendChild(title);
  textWrap.appendChild(sub);
  header.appendChild(icon);
  header.appendChild(textWrap);

  // Close button
  const closeBtn = document.createElement("button");
  Object.assign(closeBtn.style, {
    position: "absolute",
    top: "10px",
    right: "10px",
    width: "22px",
    height: "22px",
    borderRadius: "6px",
    background: "rgba(255,255,255,0.06)",
    border: "none",
    color: "#475569",
    fontSize: "11px",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    transition: "all 0.2s ease",
    padding: "0",
    lineHeight: "1"
  });
  closeBtn.textContent = "\u2715";
  closeBtn.onmouseenter = () => { closeBtn.style.background = "rgba(255,255,255,0.12)"; closeBtn.style.color = "#94a3b8"; };
  closeBtn.onmouseleave = () => { closeBtn.style.background = "rgba(255,255,255,0.06)"; closeBtn.style.color = "#475569"; };
  closeBtn.addEventListener("click", () => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(16px) scale(0.95)";
    setTimeout(() => toast.remove(), 300);
  });

  // Button row
  const btnRow = document.createElement("div");
  Object.assign(btnRow.style, {
    display: "flex",
    gap: "8px"
  });

  const rateBtn = document.createElement("a");
  rateBtn.href = "https://chromewebstore.google.com/detail/secret-sanitizer/genolcmpopiemhpbdnhkaefllchgekja/reviews";
  rateBtn.target = "_blank";
  rateBtn.rel = "noopener";
  Object.assign(rateBtn.style, {
    flex: "1",
    padding: "10px 16px",
    background: "linear-gradient(135deg, #f59e0b 0%, #eab308 50%, #f59e0b 100%)",
    backgroundSize: "200% 200%",
    color: "#0f172a",
    border: "none",
    borderRadius: "10px",
    fontSize: "12px",
    fontWeight: "700",
    cursor: "pointer",
    textAlign: "center",
    textDecoration: "none",
    transition: "all 0.25s ease",
    position: "relative",
    overflow: "hidden",
    letterSpacing: "0.02em",
    boxShadow: "0 4px 14px rgba(245,158,11,0.25)"
  });
  rateBtn.textContent = "\u2605 Rate on Chrome Store";
  rateBtn.onmouseenter = () => { rateBtn.style.transform = "translateY(-1px)"; rateBtn.style.boxShadow = "0 6px 20px rgba(245,158,11,0.35)"; };
  rateBtn.onmouseleave = () => { rateBtn.style.transform = "translateY(0)"; rateBtn.style.boxShadow = "0 4px 14px rgba(245,158,11,0.25)"; };
  rateBtn.addEventListener("click", () => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  });

  const laterBtn = document.createElement("button");
  Object.assign(laterBtn.style, {
    padding: "10px 16px",
    background: "rgba(255,255,255,0.06)",
    border: "1px solid rgba(255,255,255,0.08)",
    color: "#64748b",
    borderRadius: "10px",
    fontSize: "12px",
    fontWeight: "500",
    cursor: "pointer",
    transition: "all 0.2s ease"
  });
  laterBtn.textContent = "Later";
  laterBtn.onmouseenter = () => { laterBtn.style.background = "rgba(255,255,255,0.1)"; laterBtn.style.color = "#94a3b8"; };
  laterBtn.onmouseleave = () => { laterBtn.style.background = "rgba(255,255,255,0.06)"; laterBtn.style.color = "#64748b"; };
  laterBtn.addEventListener("click", () => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(16px) scale(0.95)";
    setTimeout(() => toast.remove(), 300);
  });

  btnRow.appendChild(rateBtn);
  btnRow.appendChild(laterBtn);

  content.appendChild(header);
  content.appendChild(btnRow);

  toast.appendChild(shimmer);
  toast.appendChild(content);
  toast.appendChild(closeBtn);
  document.body.appendChild(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0) scale(1)";
  });

  // Auto-dismiss after 20 seconds
  setTimeout(() => {
    if (toast.parentNode) {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(16px) scale(0.95)";
      setTimeout(() => toast.remove(), 300);
    }
  }, 20000);
}

// ==================== MILESTONE CELEBRATION ====================

function showMilestoneCelebration(milestone) {
  // Remove any existing celebration
  const existing = document.getElementById("ss-milestone-toast");
  if (existing) existing.remove();

  // Inject keyframes once
  if (!document.getElementById("ss-milestone-keyframes")) {
    const style = document.createElement("style");
    style.id = "ss-milestone-keyframes";
    style.textContent = `
      @keyframes ss-milestone-border {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
      }
      @keyframes ss-milestone-glow {
        0%, 100% { box-shadow: 0 8px 40px rgba(0,0,0,0.4), 0 0 30px rgba(14,165,233,0.08), inset 0 1px 0 rgba(255,255,255,0.06); }
        50% { box-shadow: 0 12px 48px rgba(0,0,0,0.5), 0 0 40px rgba(14,165,233,0.15), inset 0 1px 0 rgba(255,255,255,0.08); }
      }
      @keyframes ss-trophy-bounce {
        0%, 100% { transform: scale(1) rotate(0deg); }
        15% { transform: scale(1.2) rotate(-8deg); }
        30% { transform: scale(1.15) rotate(6deg); }
        45% { transform: scale(1.1) rotate(-4deg); }
        60% { transform: scale(1.05) rotate(2deg); }
        75% { transform: scale(1.02) rotate(-1deg); }
      }
      @keyframes ss-count-up {
        0% { opacity: 0; transform: translateY(8px) scale(0.9); }
        100% { opacity: 1; transform: translateY(0) scale(1); }
      }
      @keyframes ss-confetti-1 { 0% { transform: translateY(0) rotate(0); opacity: 1; } 100% { transform: translateY(-40px) translateX(15px) rotate(180deg); opacity: 0; } }
      @keyframes ss-confetti-2 { 0% { transform: translateY(0) rotate(0); opacity: 1; } 100% { transform: translateY(-35px) translateX(-12px) rotate(-150deg); opacity: 0; } }
      @keyframes ss-confetti-3 { 0% { transform: translateY(0) rotate(0); opacity: 1; } 100% { transform: translateY(-45px) translateX(8px) rotate(200deg); opacity: 0; } }
    `;
    document.head.appendChild(style);
  }

  // Position above the secrets-detected toast if it exists
  const secretsToast = document.querySelector('.secret-sanitizer-toast');
  const bottomOffset = secretsToast ? secretsToast.offsetHeight + 32 : 20;

  // Outer wrapper for the gradient border effect
  const wrapper = document.createElement("div");
  wrapper.id = "ss-milestone-toast";
  Object.assign(wrapper.style, {
    position: "fixed",
    bottom: bottomOffset + "px",
    right: "20px",
    padding: "1.5px",
    borderRadius: "16px",
    background: "linear-gradient(135deg, #0ea5e9, #06b6d4, #818cf8, #fbbf24, #0ea5e9)",
    backgroundSize: "300% 300%",
    animation: "ss-milestone-border 4s ease infinite, ss-milestone-glow 3s ease-in-out infinite",
    zIndex: "2147483647",
    opacity: "0",
    transform: "translateY(12px) scale(0.9)",
    transition: "all 0.5s cubic-bezier(0.16, 1, 0.3, 1)",
    maxWidth: "340px",
    pointerEvents: "none"
  });

  const toast = document.createElement("div");
  Object.assign(toast.style, {
    background: "linear-gradient(145deg, #0f172a 0%, #1e293b 40%, #0f172a 100%)",
    color: "#f1f5f9",
    borderRadius: "15px",
    padding: "18px 20px",
    fontFamily: "system-ui, -apple-system, sans-serif",
    display: "flex",
    alignItems: "center",
    gap: "14px",
    position: "relative",
    overflow: "hidden"
  });

  // Subtle radial glow behind the icon
  const bgGlow = document.createElement("div");
  Object.assign(bgGlow.style, {
    position: "absolute",
    top: "-20px",
    left: "-10px",
    width: "80px",
    height: "80px",
    background: "radial-gradient(circle, rgba(14,165,233,0.12) 0%, transparent 70%)",
    pointerEvents: "none"
  });

  // Trophy icon with bounce
  const iconWrap = document.createElement("div");
  Object.assign(iconWrap.style, {
    position: "relative",
    flexShrink: "0"
  });

  const icon = document.createElement("div");
  Object.assign(icon.style, {
    width: "42px",
    height: "42px",
    borderRadius: "14px",
    background: "linear-gradient(135deg, rgba(14,165,233,0.15) 0%, rgba(6,182,212,0.1) 50%, rgba(129,140,248,0.08) 100%)",
    border: "1px solid rgba(14,165,233,0.15)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "20px",
    animation: "ss-trophy-bounce 1s ease-out"
  });
  icon.textContent = "\uD83C\uDFC6";

  // Mini confetti particles
  const confettiColors = ["#fbbf24", "#0ea5e9", "#818cf8"];
  const confettiAnims = ["ss-confetti-1", "ss-confetti-2", "ss-confetti-3"];
  for (let i = 0; i < 3; i++) {
    const particle = document.createElement("div");
    Object.assign(particle.style, {
      position: "absolute",
      width: "4px",
      height: "4px",
      borderRadius: "50%",
      background: confettiColors[i],
      top: "8px",
      left: `${14 + i * 7}px`,
      animation: `${confettiAnims[i]} 0.8s ease-out ${0.1 + i * 0.15}s forwards`,
      opacity: "0",
      pointerEvents: "none"
    });
    // Reset opacity for animation start
    particle.style.opacity = "1";
    iconWrap.appendChild(particle);
  }

  iconWrap.appendChild(icon);

  // Text content
  const textWrap = document.createElement("div");
  Object.assign(textWrap.style, { flex: "1", minWidth: "0" });

  const count = document.createElement("div");
  Object.assign(count.style, {
    fontWeight: "800",
    fontSize: "16px",
    letterSpacing: "-0.02em",
    marginBottom: "3px",
    animation: "ss-count-up 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.2s both"
  });

  const mText = milestone >= 1000
    ? (milestone / 1000).toLocaleString() + "K"
    : milestone.toLocaleString();
  const mSpan = document.createElement("span");
  mSpan.style.cssText = "background:linear-gradient(135deg,#38bdf8,#06b6d4,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text";
  mSpan.textContent = mText;
  const protSpan = document.createElement("span");
  protSpan.style.color = "#e2e8f0";
  protSpan.textContent = " secrets protected";
  count.appendChild(mSpan);
  count.appendChild(protSpan);

  const sub = document.createElement("div");
  Object.assign(sub.style, {
    fontSize: "11px",
    color: "#64748b",
    fontWeight: "500",
    animation: "ss-count-up 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.35s both"
  });

  // Dynamic sub-text based on milestone tier
  const subTexts = {
    100: "Getting started!",
    500: "Privacy champion",
    1000: "Security pro",
    5000: "Elite protector",
    10000: "Legendary guardian",
    50000: "Unstoppable force",
    100000: "God-tier security"
  };
  const nearestSub = Object.keys(subTexts).reverse().find(k => milestone >= Number(k));
  sub.textContent = nearestSub ? `Milestone \u2022 ${subTexts[nearestSub]}` : "Milestone reached";

  textWrap.appendChild(count);
  textWrap.appendChild(sub);

  toast.appendChild(bgGlow);
  toast.appendChild(iconWrap);
  toast.appendChild(textWrap);
  wrapper.appendChild(toast);
  document.body.appendChild(wrapper);

  // Animate in
  requestAnimationFrame(() => {
    wrapper.style.opacity = "1";
    wrapper.style.transform = "translateY(0) scale(1)";
  });

  // Auto-dismiss after 5 seconds
  setTimeout(() => {
    if (wrapper.parentNode) {
      wrapper.style.opacity = "0";
      wrapper.style.transform = "translateY(8px) scale(0.95)";
      setTimeout(() => wrapper.remove(), 400);
    }
  }, 5000);
}

// ==================== MESSAGE HANDLERS ====================

chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  try {
    if (request.action === "milestone") {
      showMilestoneCelebration(request.milestone);
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