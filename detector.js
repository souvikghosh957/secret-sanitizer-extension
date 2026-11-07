// detector.js — pure secret-detection engine (no DOM, no chrome.* APIs).
// Shared by content_script.js, popup/popup.js and the Node test suite (tests/) so every
// surface masks exactly the same things. Depends on SHARED_PATTERNS from patterns.js.

const DETECTOR_CONFIG = {
  // Unnamed values must be at least this long (letters + digits) to count as random-looking.
  minRandomLength: 16,
  // Values assigned to a secret-sounding name (SIGNING_KEY=...) qualify from this length.
  minNamedSecretLength: 12,
  // Share of letter pairs that are common in code/English. Identifiers score above this,
  // random tokens below. Calibrated on npm (train) and the Python stdlib (holdout): flags
  // ~1% of long identifiers, catches 99% of 16-char base62 and 97% of 16-char letter-only tokens.
  maxRandomWordScore: 0.5,
  // Stricter for short values under a secret-sounding name, where 12 chars give less evidence.
  maxNamedWordScore: 0.4,
  // Filters out repetitive filler (xxxxxxxx, abababab) that also scores low on letter pairs.
  minRandomEntropy: 3,
  minNamedSecretEntropy: 2.5,
  // Hard cap on collected matches. Hitting it marks the scan as partial (never silent).
  maxMatches: 2000,
  // Above this size only prefixed/contextual patterns run (generic fallbacks, entropy and
  // broad PII patterns are skipped) and the scan is reported as partial. A full scan of
  // 500 KB of code/logs takes ~40 ms; the paste handler must stay synchronous.
  fullScanMaxLength: 500000
};

// Generic fallback patterns — run after all specific patterns.
const TIER2_LABELS = new Set(["QUOTED_SECRET", "LONG_RANDOM_STRING", "BASE64_SECRET"]);

// Rules that guess from the shape of a value. Only these can be allow-listed from the toast:
// a recognised key format or PII match is never unmasked by an allow-list entry.
const RANDOM_TOKEN_LABEL = "ENTROPY";
const GENERIC_LABELS = new Set([...TIER2_LABELS, RANDOM_TOKEN_LABEL]);

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
  JWT: 'eyj', DB_CONN: '://', URL_CREDENTIALS: '://', BASIC_AUTH: 'basic',
  SLACK_WEBHOOK: 'hooks.slack', TEAMS_WEBHOOK: 'webhook.office',
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

// ==================== CHECKSUMS ====================

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

// Text immediately around a match, for keyword checks.
function textAround(text, start, end, radius = 40) {
  return text.slice(Math.max(0, start - radius), Math.min(text.length, end + radius));
}

// ==================== RANDOMNESS ====================

// The 160 most common letter pairs in long code identifiers. Random tokens rarely hit them;
// identifiers built from words nearly always do. Table lookups only, so no backtracking risk.
const COMMON_BIGRAMS = "eronreesintienattedeioalorstedsentleroricondfietecvelipagesiitactatonsmeceartranngthcahaprckpesonaiseprancchomneicidctealohespexnorsssrtasocopiligmaodifdivaieptrrefladsutamshunpoelemdaadkeagksmpnfscimolotaumityurldtcdloutuniullttseettsuhobufognfrcrosegplnvllxtryuseijsueluevrndosaclwiabfeiprmhiblewmoapeoowupovquaiciddrc";
const BIGRAM_TABLE = new Uint8Array(26 * 26);
for (let i = 0; i < COMMON_BIGRAMS.length; i += 2) {
  BIGRAM_TABLE[(COMMON_BIGRAMS.charCodeAt(i) - 97) * 26 + COMMON_BIGRAMS.charCodeAt(i + 1) - 97] = 1;
}

// Share of adjacent letter/digit pairs that are common letter pairs. Separators restart the
// count, so "src/main/java" scores as three words. Case-insensitive.
function wordScore(s) {
  let hits = 0, pairs = 0, prev = -2; // prev: letter 0-25, digit -1, separator -2
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    const lower = code | 32;
    const cur = lower >= 97 && lower <= 122 ? lower - 97 : (code >= 48 && code <= 57 ? -1 : -2);
    if (cur !== -2 && prev !== -2) {
      pairs++;
      if (cur >= 0 && prev >= 0 && BIGRAM_TABLE[prev * 26 + cur]) hits++;
    }
    prev = cur;
  }
  return pairs ? hits / pairs : 0;
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

// abcdefgh..., 0123456789...: sample values and alphabet constants, not secrets.
function isMostlySequential(s) {
  let steps = 0;
  for (let i = 1; i < s.length; i++) if (s.charCodeAt(i) - s.charCodeAt(i - 1) === 1) steps++;
  return steps / (s.length - 1) > 0.5;
}

const onlyAlnum = (s) => s.replace(/[^A-Za-z0-9]/g, "");
const isHex = (s) => /^[0-9a-f]+$/i.test(s);
// Timestamps, phone numbers, long numeric ids: at most one letter in five.
const isMostlyDigits = (s) => s.replace(/\D/g, "").length / s.length > 0.8;

// True when a value looks machine-generated rather than words glued together. Bare hex is
// handled separately (hashes, commit ids), so it never qualifies here.
function looksRandom(s) {
  const alnum = onlyAlnum(s);
  if (alnum.length < DETECTOR_CONFIG.minRandomLength) return false;
  if (isHex(alnum) || isMostlyDigits(alnum) || isMostlySequential(alnum)) return false;
  return wordScore(s) < DETECTOR_CONFIG.maxRandomWordScore &&
    calculateEntropy(alnum) >= DETECTOR_CONFIG.minRandomEntropy;
}

// Token with separators (pod names, ARNs, file names, license keys): random if any segment is,
// or, for dashed serials like aB3d-eF5g-hI7j-kL9m, if no segment is a recognisable word.
function isRandomToken(token) {
  const segments = token.split(/[^A-Za-z0-9]+/).filter(Boolean);
  if (segments.some(looksRandom)) return true;
  if (segments.length < 2 || segments.some(seg => seg.length < 3)) return false;
  const isWord = (seg) => /^[A-Za-z]+$/.test(seg) && wordScore(seg) >= DETECTOR_CONFIG.maxRandomWordScore;
  return !segments.some(isWord) && looksRandom(segments.join(""));
}

// Value assigned to a secret-sounding name. Hex counts here; references (config.apiToken)
// and readable sample values (your-token-here) don't.
function isNamedSecretValue(token) {
  const alnum = onlyAlnum(token);
  if (alnum.length < DETECTOR_CONFIG.minNamedSecretLength || isMostlySequential(alnum)) return false;
  if (calculateEntropy(alnum) < DETECTOR_CONFIG.minNamedSecretEntropy) return false;
  if (isHex(alnum)) return /[a-f]/i.test(alnum);
  if (isMostlyDigits(alnum)) return false;
  // Dotted values are usually references (body.byteOffset) unless a segment is clearly random.
  return isRandomToken(token) || (!token.includes(".") && wordScore(token) < DETECTOR_CONFIG.maxNamedWordScore);
}

// ==================== VALUE CONTEXT ====================

// What the name a value is assigned to says about that value.
const VALUE_BARE = 0;   // no name
const VALUE_NAMED = 1;  // ordinary name (GH_OLD=...)
const VALUE_ID = 2;     // *_id: usually public, though a random one still gets masked
const VALUE_SECRET = 3; // secret-sounding name (webhook_secret: ...)
const VALUE_PLAIN = 4;  // names that hold non-secrets (etag, commit, requestId, ?list=)

const TRACE_NAME_RE = /(?:request|trace|span|correlation|parent|transaction)[_.\-]?id$/i;
const ID_NAME_RE = /(?:[_.\-][iI][dD]|[a-z]I[dD])$/;
const SECRET_NAME_RE = /secret|passw|passphrase|pwd|credential|cookie|csrf|xsrf|session|signature|signing|token|api[_-]?key|private[_-]?key|access[_-]?key|auth(?!or(?!i[sz]))|jwt|[_.\-](?:key|sig)$/i;
const CAMEL_KEY_NAME_RE = /[a-z]Key$/;
// Secret-sounding, but these keys and token fields name ordinary data.
const NON_SECRET_KEY_NAME_RE = /(?:public|cache|primary|foreign|sort|partition|object|routing|hash|row|idempotency|composite|unique|index|lookup)[_.\-]?key$|tokens?(?:izer|[_-]?count|[_-]?type|[_-]?usage)$/i;
const QUERY_SECRET_NAME_RE = /^(?:key|code|sig|sid|pass|state|nonce)$/i;
// URL parameters that are public by design. Any other random-looking parameter gets masked.
const PUBLIC_QUERY_NAME_RE = /^(?:id|v|list|playlist|q|query|search|page|ref|lang|locale|utm_\w+|gclid|fbclid|msclkid)$/i;
const HASH_NAME_RE = /(?:hash|digest|checksum|etag|integrity|fingerprint|commit|revision|sha\d{0,3}|md5|traceparent|tracestate)$/i;

const isNameChar = (c) => c !== undefined && /[\w.\-]/.test(c);
const skipBack = (text, i, chars) => {
  for (let n = 0; n < 8 && chars.includes(text[i]) && i >= 0; n++) i--;
  return i;
};

// Classifies a value by the name in front of it (name = value, "name": "value", name => value,
// name := value). A plain backward scan: this runs for every long token in the paste.
function valueContext(text, start) {
  let i = skipBack(text, skipBack(text, start - 1, `'"`), " \t");
  const op = text[i];
  if (op === ">" && text[i - 1] === "=") i -= 2;
  else if (op === "=") i -= text[i - 1] === ":" ? 2 : 1;
  else if (op === ":" || op === "：") i--;
  else return VALUE_BARE;
  const end = skipBack(text, skipBack(text, i, " \t"), `'"`) + 1;

  let nameStart = end;
  while (nameStart > 0 && end - nameStart < 64 && isNameChar(text[nameStart - 1])) nameStart--;
  if (nameStart === end) return VALUE_BARE;
  const name = text.slice(nameStart, end);
  const inQuery = "?&#;".includes(text[nameStart - 1] || " ");

  if (TRACE_NAME_RE.test(name)) return VALUE_PLAIN;
  const secretName = !NON_SECRET_KEY_NAME_RE.test(name) && (SECRET_NAME_RE.test(name) ||
    CAMEL_KEY_NAME_RE.test(name) || (inQuery && QUERY_SECRET_NAME_RE.test(name)));
  // ?session_id= in a URL is a live credential; session_id in code is usually just a reference.
  if (ID_NAME_RE.test(name)) return inQuery && secretName ? VALUE_SECRET : VALUE_ID;
  if (secretName) return VALUE_SECRET;
  if (HASH_NAME_RE.test(name) || (inQuery && PUBLIC_QUERY_NAME_RE.test(name))) return VALUE_PLAIN;
  return VALUE_NAMED;
}

// ==================== VALIDATORS ====================
// Post-match checks that reject structurally impossible or non-secret values. Each receives
// (value, text, start, end) and returns false to drop the match.

const PATTERN_VALIDATORS = {
  CREDIT_CARD: (v, text, s, e) => !isPartOfLargerToken(text, s, e) && luhnValid(v.replace(/\D/g, '')),
  // Verhoeff still passes 1 in 10 random 12-digit numbers, so also require the printed
  // #### #### #### grouping or a keyword nearby.
  AADHAAR: (v, text, s, e) => !isPartOfLargerToken(text, s, e) && verhoeffValid(v.replace(/\D/g, '')) &&
    (/^\d{4}[ -]\d{4}[ -]\d{4}$/.test(v) || /aadha?ar|uidai|(?<![a-z])uid(?![a-z])/i.test(textAround(text, s, e))),
  IFSC: (v, text, s, e) => /ifsc|neft|rtgs|bank/i.test(textAround(text, s, e)),
  // A quoted literal under a secret-sounding name is masked even if it reads like words.
  QUOTED_SECRET: (v, text, s) => {
    const context = valueContext(text, s);
    return context !== VALUE_PLAIN && (context === VALUE_SECRET || looksRandom(v));
  },
  // Bare hex is a hash or commit id unless it's being assigned (OLD_TOKEN=<hex>).
  LONG_RANDOM_STRING: (v, text, s) => {
    const context = valueContext(text, s);
    if (context === VALUE_PLAIN || isMostlyDigits(v)) return false;
    if (isHex(v)) return context === VALUE_SECRET || context === VALUE_NAMED;
    return context === VALUE_SECRET || looksRandom(v);
  },
  BASE64_SECRET: (v, text, s) => {
    const context = valueContext(text, s);
    if (context === VALUE_PLAIN) return false;
    return context === VALUE_SECRET || (/\d/.test(v) && /[a-z]/.test(v) && /[A-Z]/.test(v) && looksRandom(v));
  },
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
  return { tier1, tier2, randomTokens: !disabled.has(RANDOM_TOKEN_LABEL) };
}

// ==================== MATCHING ====================

// Runs compiled patterns against text, pushing matches into out. alreadyFound counts
// matches from earlier tiers toward the cap; matches overlapping excluded spans are dropped.
// Returns true if the match cap was hit (caller must report the scan as partial).
function runPatterns(patterns, text, textLower, out, isLargeText, alreadyFound = 0, excluded = []) {
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

        if (overlapsSpan(excluded, start, end) || (validate && !validate(original, text, start, end))) {
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

// Values that look random but are public by construction: embedded files, content hashes,
// public keys and certificates, and URL hosts/paths. Generic rules skip these; specific
// patterns still run, so a known key format inside one is still masked. Each alternative
// starts at a literal and consumes what it scans, which keeps the pass linear.
const NON_SECRET_SPAN_RE = new RegExp([
  String.raw`\bdata:[\w\/+.\-]+(?:;[\w=\-]+)*;base64,[A-Za-z0-9+\/=]+`,
  String.raw`\b(?:(?:sha|SHA)(?:1|224|256|384|512)|md5|MD5|blake2[bs]?|h1)[:=\-][A-Za-z0-9+\/=]{20,}`,
  String.raw`(?<![A-Za-z0-9+\/])(?:iVBORw0KGgo|R0lGOD|JVBERi0|\/9j\/4)[A-Za-z0-9+\/=]+`,
  String.raw`-----BEGIN (?:CERTIFICATE(?: REQUEST)?|(?:RSA )?PUBLIC KEY|PGP PUBLIC KEY BLOCK)-----[A-Za-z0-9+\/=\s:.]*-----END [A-Z ]+-----`,
  String.raw`\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+) AAAA[A-Za-z0-9+\/=]+`,
  // Connection strings put more settings after ';' or ',' and those can be secrets, so stop there.
  String.raw`:\/\/[^\s?#"'\x60<>;,&]*`
].join("|"), "g");

// Sorted, non-overlapping [start, end] pairs. A URL's query and fragment stay out (values there
// are judged by parameter name), and so does its user:password@ part.
function findNonSecretSpans(text) {
  const spans = [];
  for (const m of text.matchAll(NON_SECRET_SPAN_RE)) {
    let start = m.index;
    if (m[0].startsWith("://")) {
      const at = m[0].indexOf("@");
      const slash = m[0].indexOf("/", 3);
      if (at !== -1 && (slash === -1 || at < slash)) start += at + 1;
    }
    spans.push([start, m.index + m[0].length]);
  }
  return spans;
}

function overlapsSpan(spans, start, end) {
  let lo = 0, hi = spans.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (spans[mid][1] <= start) lo = mid + 1; else hi = mid;
  }
  return lo < spans.length && spans[lo][0] < end;
}

function findRandomTokens(text, excluded) {
  const candidates = [];
  // Contiguous runs of ASCII non-delimiter characters. '=' is a delimiter so KEY=value only
  // masks the value; '&' and '?' split URL query parameters. Non-ASCII also delimits: Japanese
  // has no spaces, and a whole sentence must not read as one token.
  const wordRegex = /[^\s"'`()[\]{},;=&?\u0080-\uffff]+/g;
  let wordMatch;

  while ((wordMatch = wordRegex.exec(text)) !== null) {
    const word = wordMatch[0];
    if (word.length < DETECTOR_CONFIG.minNamedSecretLength) continue;
    const trimmed = word.replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, "");
    if (onlyAlnum(trimmed).length < DETECTOR_CONFIG.minNamedSecretLength) continue;

    const start = wordMatch.index + word.indexOf(trimmed);
    const end = start + trimmed.length;
    if (overlapsSpan(excluded, start, end)) continue;

    // Skip if next to brackets (likely already a placeholder)
    const context = text.substring(Math.max(0, start - 2), Math.min(text.length, end + 2));
    if (context.includes('[') || context.includes(']')) continue;

    const valueKind = valueContext(text, start);
    if (valueKind === VALUE_PLAIN) continue;
    if (valueKind === VALUE_SECRET ? !isNamedSecretValue(trimmed) : !isRandomToken(trimmed)) continue;

    candidates.push({ start, end, label: RANDOM_TOKEN_LABEL, original: trimmed });
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
// Priority: specific patterns, then generic fallbacks, then random tokens — a lower tier only
// fills gaps the tiers above left, so labels stay as precise as possible.
function findSecrets(text, compiled) {
  if (!text) return { matches: [], partial: false };
  const fullScan = text.length <= DETECTOR_CONFIG.fullScanMaxLength;
  const textLower = text.toLowerCase();

  const specific = [];
  let capped = runPatterns(compiled.tier1, text, textLower, specific, !fullScan);
  let matches = resolveOverlaps(specific);

  if (!capped && fullScan) {
    const excluded = findNonSecretSpans(text);
    const generic = [];
    capped = runPatterns(compiled.tier2, text, textLower, generic, false, specific.length, excluded);
    matches = mergeNonOverlapping(matches, resolveOverlaps(generic));
    if (!capped && compiled.randomTokens) {
      matches = mergeNonOverlapping(matches, findRandomTokens(text, excluded));
    }
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

// ==================== ALLOW-LIST ====================
// "Don't mask this again" stores a salted hash, never the value, and the paste handler must
// stay synchronous — hence SHA-256 here rather than the async crypto.subtle.

const SHA256_K = new Uint32Array(64);
const SHA256_INIT = new Uint32Array(8);
{
  let n = 0;
  for (let p = 2; n < 64; p++) {
    let prime = true;
    for (let d = 2; d * d <= p; d++) if (p % d === 0) { prime = false; break; }
    if (!prime) continue;
    if (n < 8) SHA256_INIT[n] = (Math.sqrt(p) % 1) * 2 ** 32;
    SHA256_K[n++] = (Math.cbrt(p) % 1) * 2 ** 32;
  }
}

function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const padded = new Uint8Array((((bytes.length + 8) >> 6) + 1) * 64);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bytes.length / 2 ** 29));
  view.setUint32(padded.length - 4, bytes.length << 3);

  const h = SHA256_INIT.slice();
  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + SHA256_K[i] + w[i]) | 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  return Array.from(h, x => x.toString(16).padStart(8, "0")).join("");
}

function allowedValueHash(salt, value) {
  return sha256Hex(salt + value);
}

// Drops generic matches whose value the user allowed. Specific rules are never affected.
function dropAllowedValues(matches, allowedHashes, salt) {
  if (!salt || !allowedHashes || allowedHashes.size === 0) return matches;
  return matches.filter(m => !(GENERIC_LABELS.has(m.label) && allowedHashes.has(allowedValueHash(salt, m.original))));
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
    DETECTOR_CONFIG, GENERIC_LABELS, compilePatterns, findSecrets, maskText, calculateEntropy,
    luhnValid, verhoeffValid, newPasteId, makePlaceholder, findPlaceholders,
    placeholderLabel, PLACEHOLDER_TEST_RE, wordScore, looksRandom, sha256Hex, allowedValueHash,
    dropAllowedValues
  };
}
