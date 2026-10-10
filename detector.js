// detector.js — pure secret-detection engine (no DOM, no chrome.* APIs).
// Shared by content_script.js, popup/popup.js and the Node test suite (tests/) so every
// surface masks exactly the same things. Depends on SHARED_PATTERNS from patterns.js.

const DETECTOR_CONFIG = {
  minEntropyLength: 12,
  entropyThreshold: 4.2,
  // Hard cap on collected matches. Hitting it marks the scan as partial (never silent).
  maxMatches: 2000,
  // Above this size only prefixed/contextual patterns run (generic fallbacks, entropy and
  // broad PII patterns are skipped) and the scan is reported as partial. A full scan of
  // 500 KB of code/logs takes ~40 ms; the paste handler must stay synchronous.
  fullScanMaxLength: 500000
};

// Generic fallback patterns — run after all specific patterns.
const TIER2_LABELS = new Set(["QUOTED_SECRET", "LONG_RANDOM_STRING", "BASE64_SECRET"]);

// Broad patterns without distinctive prefixes — skipped above fullScanMaxLength.
const LARGE_TEXT_SKIP_LABELS = new Set([
  "CREDIT_CARD", "AADHAAR", "PAN", "GSTIN", "IFSC",
  "DRIVING_LICENSE", "TELEGRAM_BOT_TOKEN", "TWILIO_SID",
]);

// Literal guard strings (lowercase) — checked via fast includes() before running regex.
// If the guard substring isn't in the text, the regex is skipped entirely.
const PATTERN_GUARDS = {
  AWS_KEY: 'akia', AWS_TEMP_KEY: 'asia',
  AZURE_SECRET: 'azure', GOOGLE_API_KEY: 'aiza',
  GITHUB_TOKEN: 'gh', GITHUB_FINE_PAT: 'github_pat_',
  GITLAB_TOKEN: 'glpat-', GITLAB_TRIGGER_TOKEN: 'glptt-',
  JWT: 'eyj', DB_CONN: '://', URL_CREDENTIALS: '://',
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

// ==================== VALIDATORS ====================
// Post-match checks that reject structurally impossible values. Each receives
// (value, text, start, end) and returns false to drop the match.

function luhnValid(digits) {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

const VERHOEFF_D = [
  [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
  [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
  [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]
];
const VERHOEFF_P = [
  [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
  [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]
];

// Aadhaar numbers carry a Verhoeff check digit
function verhoeffValid(digits) {
  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digits.charCodeAt(digits.length - 1 - i) - 48]];
  }
  return c === 0;
}

// True when the match is glued to a larger identifier (e.g. the tail of a UUID
// "…-426614174000" or a dotted version string) rather than standing alone.
function isPartOfLargerToken(text, start, end) {
  const glue = /[-./]/;
  const alnum = /[A-Za-z0-9]/;
  if (start >= 2 && glue.test(text[start - 1]) && alnum.test(text[start - 2])) return true;
  if (end + 1 < text.length && glue.test(text[end]) && alnum.test(text[end + 1])) return true;
  return false;
}

// Value is the right-hand side of an assignment (KEY=value, key: value)
function isAssignedValue(text, start) {
  return /[=:]\s*['"]?$/.test(text.slice(Math.max(0, start - 4), start));
}

const PATTERN_VALIDATORS = {
  CREDIT_CARD: (v, text, s, e) => !isPartOfLargerToken(text, s, e) && luhnValid(v.replace(/\D/g, '')),
  AADHAAR: (v, text, s, e) => !isPartOfLargerToken(text, s, e) && verhoeffValid(v.replace(/\D/g, '')),
  // Random 40+ char tokens virtually always contain a digit; long identifiers and paths don't.
  // Bare 40-char lowercase hex is a git SHA unless it's being assigned (OLD_TOKEN=<hex>).
  LONG_RANDOM_STRING: (v, text, s) => /\d/.test(v) && !(/^[0-9a-f]{40}$/.test(v) && !isAssignedValue(text, s)),
  BASE64_SECRET: (v) => /\d/.test(v) && /[a-z]/.test(v) && /[A-Z]/.test(v),
};

// ==================== COMPILATION ====================

// Always creates NEW RegExp instances (no shared lastIndex state between contexts).
// Patterns with a (?<secret>...) group get the `d` flag so only that span is masked.
function compilePatterns(patterns, disabledLabels) {
  const disabled = disabledLabels instanceof Set ? disabledLabels : new Set(disabledLabels || []);
  const tier1 = [];
  const tier2 = [];
  for (const [pattern, label] of patterns) {
    if (disabled.has(label)) continue;
    let flags = pattern.flags;
    const hasSecretGroup = pattern.source.includes('(?<secret>');
    if (hasSecretGroup && !flags.includes('d')) flags += 'd';
    const compiled = {
      regex: new RegExp(pattern.source, flags),
      label,
      guard: PATTERN_GUARDS[label] || null,
      skipOnLargeText: LARGE_TEXT_SKIP_LABELS.has(label),
      hasSecretGroup,
      validate: PATTERN_VALIDATORS[label] || null
    };
    (TIER2_LABELS.has(label) ? tier2 : tier1).push(compiled);
  }
  return { tier1, tier2 };
}

// ==================== MATCHING ====================

// Runs compiled patterns against text, pushing matches into out. alreadyFound counts
// matches from earlier tiers toward the cap.
// Returns true if the match cap was hit (caller must report the scan as partial).
function runPatterns(patterns, text, textLower, out, isLargeText, alreadyFound = 0) {
  for (const { regex, label, guard, skipOnLargeText, hasSecretGroup, validate } of patterns) {
    if (isLargeText && skipOnLargeText) continue;
    if (guard && !textLower.includes(guard)) continue;

    regex.lastIndex = 0;
    let match;
    try {
      while ((match = regex.exec(text)) !== null) {
        if (match[0].length === 0) {
          regex.lastIndex = match.index + 1;
          continue;
        }

        let start = match.index;
        let end = start + match[0].length;
        let original = match[0];
        if (hasSecretGroup) {
          const span = match.indices?.groups?.secret;
          if (!span) continue;
          [start, end] = span;
          original = text.slice(start, end);
        }

        if (validate && !validate(original, text, start, end)) {
          if (!regex.global) break;
          continue;
        }

        out.push({ start, end, label, original });
        if (alreadyFound + out.length >= DETECTOR_CONFIG.maxMatches) return true;
        if (!regex.global) break;
      }
    } finally {
      regex.lastIndex = 0;
    }
  }
  return false;
}

// Keep non-overlapping matches (prefer earlier, then longer). Returns a new sorted array.
function resolveOverlaps(matches) {
  const sorted = [...matches].sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const kept = [];
  for (const m of sorted) {
    if (kept.length === 0 || m.start >= kept[kept.length - 1].end) kept.push(m);
  }
  return kept;
}

function calculateEntropy(str) {
  if (!str) return 0;
  const freq = new Map();
  for (const char of str) freq.set(char, (freq.get(char) || 0) + 1);
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function findHighEntropySecrets(text) {
  const candidates = [];
  // Contiguous runs of non-whitespace, non-delimiter characters. '=' is a delimiter so
  // KEY=value only masks the value; '&' and '?' split URL query parameters.
  const wordRegex = /[^\s"'`()[\]{},;=&?]+/g;
  const seen = new Set();
  let wordMatch;

  while ((wordMatch = wordRegex.exec(text)) !== null) {
    const word = wordMatch[0];
    const trimmed = word.replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, "");
    if (trimmed.length < DETECTOR_CONFIG.minEntropyLength) continue;

    // Plain links are not secrets; credentials inside URLs are handled by URL_CREDENTIALS
    if (word.includes('://')) continue;

    const alphanumOnly = trimmed.replace(/[^A-Za-z0-9]/g, "");
    if (alphanumOnly.length < DETECTOR_CONFIG.minEntropyLength) continue;
    if (calculateEntropy(alphanumOnly) < DETECTOR_CONFIG.entropyThreshold) continue;

    const start = wordMatch.index + word.indexOf(trimmed);
    const end = start + trimmed.length;

    // Skip if next to brackets (likely already a placeholder)
    const context = text.substring(Math.max(0, start - 2), Math.min(text.length, end + 2));
    if (context.includes('[') || context.includes(']')) continue;

    if (seen.has(`${start}:${trimmed}`)) continue;
    seen.add(`${start}:${trimmed}`);
    candidates.push({ start, end, label: 'ENTROPY', original: trimmed });
  }

  return candidates;
}

// Adds lower-priority candidates (sorted by start) that don't overlap any existing
// higher-priority match (resolved, sorted). Returns a new sorted array.
function mergeNonOverlapping(matches, extra) {
  if (extra.length === 0) return matches;
  const merged = [...matches];
  let i = 0;
  for (const c of extra) {
    while (i < matches.length && matches[i].end <= c.start) i++;
    if (i < matches.length && matches[i].start < c.end) continue;
    merged.push(c);
  }
  return merged.sort((a, b) => a.start - b.start);
}

// Full detection pass. Returns { matches, partial } where matches are non-overlapping,
// sorted, in original-text coordinates. partial = some checks were skipped (huge text
// or match cap) — callers must tell the user instead of implying the text is clean.
// Priority: specific patterns, then generic fallbacks, then entropy — a lower tier only
// fills gaps the tiers above left, so labels stay as precise as possible.
function findSecrets(text, compiled) {
  if (!text) return { matches: [], partial: false };
  const fullScan = text.length <= DETECTOR_CONFIG.fullScanMaxLength;
  const textLower = text.toLowerCase();

  const specific = [];
  let capped = runPatterns(compiled.tier1, text, textLower, specific, !fullScan);
  let matches = resolveOverlaps(specific);

  if (!capped && fullScan) {
    const generic = [];
    capped = runPatterns(compiled.tier2, text, textLower, generic, false, specific.length);
    matches = mergeNonOverlapping(matches, resolveOverlaps(generic));
  }
  if (!capped && fullScan) {
    matches = mergeNonOverlapping(matches, findHighEntropySecrets(text));
  }

  return { matches, partial: capped || !fullScan };
}

// Builds the masked text in one left-to-right pass.
// placeholderFor(label, index) returns the replacement string for the index-th match.
function maskText(text, matches, placeholderFor) {
  const replacements = [];
  const parts = [];
  let cursor = 0;
  for (const m of matches) {
    if (m.start > cursor) parts.push(text.substring(cursor, m.start));
    const placeholder = placeholderFor(m.label, replacements.length);
    parts.push(placeholder);
    replacements.push([placeholder, m.original]);
    cursor = m.end;
  }
  if (cursor < text.length) parts.push(text.substring(cursor));
  return { maskedText: parts.join(''), replacements };
}

// ==================== PLACEHOLDERS ====================
// Format: [LABEL_<pasteId>_<n>], e.g. [OPENAI_KEY_k3f9_0]. The random per-paste id keeps
// placeholders from different pastes distinct, so Smart Restore can never return the
// wrong secret and the AI never sees two different secrets under one name.

const PLACEHOLDER_SOURCE = String.raw`\[[A-Z][A-Z0-9_]*_[a-z0-9]{4}_\d+\]`;
const PLACEHOLDER_TEST_RE = new RegExp(PLACEHOLDER_SOURCE);
const PLACEHOLDER_LABEL_RE = /^\[([A-Z][A-Z0-9_]*)_[a-z0-9]{4}_\d+\]$/;

function newPasteId() {
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  return Array.from(bytes, b => (b % 36).toString(36)).join('');
}

function makePlaceholder(label, pasteId, index) {
  return `[${label}_${pasteId}_${index}]`;
}

// Returns every placeholder token in text (in order, may repeat)
function findPlaceholders(text) {
  return text.match(new RegExp(PLACEHOLDER_SOURCE, 'g')) || [];
}

function placeholderLabel(placeholder) {
  const m = PLACEHOLDER_LABEL_RE.exec(placeholder);
  return m ? m[1] : null;
}

if (typeof module !== "undefined") {
  module.exports = {
    DETECTOR_CONFIG, compilePatterns, findSecrets, maskText, calculateEntropy,
    luhnValid, verhoeffValid, newPasteId, makePlaceholder, findPlaceholders,
    placeholderLabel, PLACEHOLDER_TEST_RE
  };
}
