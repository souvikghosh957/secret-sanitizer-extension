// Shared secret detection patterns — used by both content_script.js and popup.js.
// If you add/change a pattern here, both contexts pick it up automatically.
//
// Order: specific prefixed patterns first, then contextual, then generic (last resort)
const SHARED_PATTERNS = [
  // === CLOUD PROVIDER KEYS ===
  // AWS
  [/\bAKIA[0-9A-Z]{16}\b/gi, "AWS_KEY"],
  [/\bASIA[0-9A-Z]{16}\b/gi, "AWS_TEMP_KEY"],
  // Azure (contextual — only near azure-specific keywords)
  [/(?:azure|tenant[_\s-]?id|AZURE_[A-Z_]+)\s*[=:]\s*['"]?[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}['"]?/gi, "AZURE_SECRET"],
  // Google
  [/\bAIza[0-9A-Za-z\-_]{35,}\b/g, "GOOGLE_API_KEY"],

  // === VCS & CI/CD TOKENS ===
  [/\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g, "GITHUB_TOKEN"],
  [/\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, "GITHUB_FINE_PAT"],
  [/\bglpat-[A-Za-z0-9\-_]{20,}\b/g, "GITLAB_TOKEN"],
  [/\bglptt-[A-Za-z0-9\-_]{20,}\b/g, "GITLAB_TRIGGER_TOKEN"],

  // === JWT TOKENS ===
  [/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "JWT"],

  // === DATABASE CONNECTIONS ===
  [/(mongodb|postgres|mysql|redis|amqp|amqps):\/\/[^:\s]+:[^@\s]+@[^\s]+/gi, "DB_CONN"],

  // === CREDIT CARDS ===
  // Visa, Mastercard, Amex, Diners Club (30x/36x/38x), Discover
  // Supports contiguous digits and common separators (dash/space between 4-digit groups)
  [/\b(?:4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}|5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}|3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}|3(?:0[0-5]|[68][0-9])[0-9][\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{2}|6(?:011|5[0-9]{2})[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b/g, "CREDIT_CARD"],

  // === PAYMENT PLATFORMS ===
  // Stripe
  [/\bsk_live_[A-Za-z0-9]{24,}\b/gi, "STRIPE_KEY"],
  [/\bsk_test_[A-Za-z0-9]{24,}\b/gi, "STRIPE_TEST_KEY"],
  [/\bpk_live_[A-Za-z0-9]{24,}\b/gi, "STRIPE_PUB_KEY"],
  [/\bpk_test_[A-Za-z0-9]{24,}\b/gi, "STRIPE_TEST_PUB_KEY"],
  // Square
  [/\bsq0atp-[A-Za-z0-9\-_]{22,}\b/g, "SQUARE_ACCESS_TOKEN"],
  [/\bsq0csp-[A-Za-z0-9\-_]{22,}\b/g, "SQUARE_SECRET"],
  // Razorpay
  [/\brzp_live_[A-Za-z0-9]{14,}\b/gi, "RAZORPAY_KEY"],
  [/\brzp_test_[A-Za-z0-9]{14,}\b/gi, "RAZORPAY_TEST_KEY"],
  // Paytm
  [/\bpaytm[_\s-]?(?:key|secret|token)[\s:=]+['"]?[A-Za-z0-9]{20,}['"]?/gi, "PAYTM_KEY"],
  [/\b(?:merchant[_\s-]?key|merchant[_\s-]?id)[\s:=]+['"]?[A-Za-z0-9]{20,}['"]?/gi, "PAYTM_MERCHANT"],

  // === COMMUNICATION & MESSAGING ===
  // Twilio
  [/\bAC[a-z0-9]{32}\b/g, "TWILIO_SID"],
  [/\b(?:twilio[_\s-]?auth[_\s-]?token|auth[_\s-]?token)[\s:=]+['"]?[A-Za-z0-9]{32,}['"]?/gi, "TWILIO_AUTH_TOKEN"],
  // Slack (xoxb=bot, xoxp=user, xoxa=app, xoxr=refresh, xoxs=session, xoxe=expiring)
  [/\bxox[bpsare]-[A-Za-z0-9\-]{10,}\b/g, "SLACK_TOKEN"],
  // Discord webhook
  [/\bhttps:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+\b/g, "DISCORD_WEBHOOK"],
  // Telegram bot
  [/\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g, "TELEGRAM_BOT_TOKEN"],
  // SendGrid
  [/\bSG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}\b/g, "SENDGRID_KEY"],
  // Mailgun (contextual to avoid "key-value" false positives)
  [/(?:mailgun|MAILGUN_API_KEY)\s*[=:]\s*['"]?key-[a-z0-9]{32,}['"]?/gi, "MAILGUN_KEY"],

  // === AI & ML PLATFORMS ===
  [/\bsk-ant-[A-Za-z0-9\-_]{32,}\b/g, "ANTHROPIC_KEY"],
  [/\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9\-_]{32,}\b/gi, "OPENAI_KEY"],
  [/\bgsk_[A-Za-z0-9]{48,}\b/gi, "GROQ_KEY"],
  [/\bhf_[A-Za-z0-9]{34,}\b/g, "HUGGINGFACE_TOKEN"],

  // === CLOUD PLATFORMS ===
  // Firebase
  [/\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}\b/g, "FIREBASE_KEY"],
  // Heroku (contextual — only near heroku/api keywords to avoid UUID false positives)
  [/(?:heroku[_\s-]?api[_\s-]?key|HEROKU_API_KEY)\s*[=:]\s*['"]?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['"]?/gi, "HEROKU_API_KEY"],
  // Vercel (vc prefixed tokens)
  [/\bvc[pcirka]_[A-Za-z0-9_\-]{24,}\b/g, "VERCEL_TOKEN"],
  // DigitalOcean
  [/\bdop_v1_[a-f0-9]{64}\b/g, "DIGITALOCEAN_TOKEN"],
  [/\bdoctl-[A-Za-z0-9\-]{40,}\b/g, "DIGITALOCEAN_REFRESH"],
  // Supabase
  [/\bsbp_[a-f0-9]{40,}\b/g, "SUPABASE_TOKEN"],
  // Cloudflare (contextual — no distinct prefix, so require keyword context)
  [/(?:cloudflare|CF_API_TOKEN|CF_API_KEY)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{37,}['"]?/gi, "CLOUDFLARE_TOKEN"],
  // Datadog (contextual — only near datadog/dd keywords to avoid hex false positives)
  [/(?:datadog|dd)[_\s-]?(?:api[_\s-]?key|app[_\s-]?key|DD_API_KEY|DD_APP_KEY)\s*[=:]\s*['"]?[a-f0-9]{32,}['"]?/gi, "DATADOG_KEY"],

  // === E-COMMERCE ===
  // Shopify
  [/\bshp(?:at|ca|pa|ss|ua)_[A-Za-z0-9]{32,}\b/g, "SHOPIFY_TOKEN"],

  // === PACKAGE REGISTRIES ===
  [/\bnpm_[A-Za-z0-9]{36,}\b/g, "NPM_TOKEN"],
  [/\bpypi-[A-Za-z0-9\-_]{50,}\b/g, "PYPI_TOKEN"],

  // === INDIAN PII ===
  [/\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g, "AADHAAR"],
  [/\b[A-Z]{5}\d{4}[A-Z]{1}\b/g, "PAN"],
  [/(?:\+91[\s-]?|(?:phone|mobile|cell|contact|mob|tel|whatsapp)[\s:=]+['"]?)\b[6-9]\d{9}\b/gi, "INDIAN_PHONE"],
  [/\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}Z[A-Z\d]{1}\b/gi, "GSTIN"],
  [/\b[A-Z]{4}0[A-Z0-9]{6}\b/gi, "IFSC"],
  [/\b[\w\.-]+@(?:oksbi|okaxis|okhdfcbank|okicici|oksbp|ybl|apl|airtel)\b/gi, "UPI_ID"],
  [/\b[\w\.-]+@upi\b/gi, "UPI_ID_GENERIC"],
  [/\b(?:success|failure|test)@(?:upi|razorpay|payu)\b/gi, "UPI_TEST_ID"],
  [/\b[\w\.-]+@(?:razorpay|payu|paytm)\b/gi, "PAYMENT_UPI_ID"],
  [/\b[A-Z]{2}[0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{7}\b/gi, "DRIVING_LICENSE"],
  [/(?:voter[\s-]?id|epic|election[\s-]?id)[\s:=]+['"]?\b[A-Z]{3}[0-9]{7}\b['"]?/gi, "VOTER_ID"],
  [/(?:passport)[\s:=_-]*(?:no|number|num|#)?[\s:=_-]+['"]?\b[A-PR-V][1-9]\d{6}\b['"]?/gi, "PASSPORT"],
  [/(?:vehicle|registration|reg[\s-]?no|number[\s-]?plate|license[\s-]?plate)[\s:=]+['"]?\b[A-Z]{2}\d{1,2}[A-Z]{1,2}\d{4}\b['"]?/gi, "VEHICLE_REG"],

  // === SENSITIVE CONTEXT PATTERNS ===
  [/(?:otp|pin|code|verification)[\s:=]+['"]?(\d{4,8})['"]?/gi, "OTP_CODE"],
  [/\b(?:enter|your|the)[\s]+(?:otp|pin|code)[\s:]+(\d{4,8})\b/gi, "OTP_CODE"],
  [/(?:password|passwd|pwd|secret|key|token|api)(?:\s+is)?[\s:=]+['"]?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}['"]?/gi, "EMAIL_IN_SECRET"],
  [/(?:password|passwd|pwd)(?:\s+is)?[\s:=]+['"]?[A-Za-z0-9!@#$%^&*()_+\-=.]{8,}['"]?/gi, "PASSWORD_HINT"],
  // Negative lookahead: skip values that start with a known specific-pattern prefix
  // (those are better matched by their dedicated patterns above)
  [/\b(bearer|token)[\s:]+(?!ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|glptt-|sk_live_|sk_test_|pk_live_|pk_test_|sk-ant-|sk-(?:proj-)?[A-Za-z0-9]|xox[bpsare]-|npm_|hf_|gsk_|rzp_|shp(?:at|ca|pa|ss|ua)_|sq0|sbp_|dop_v1_|vc[pcirka]_)[A-Za-z0-9\-_.]{20,}\b/gi, "BEARER_TOKEN"],

  // === KEY=VALUE FORMAT PATTERNS ===
  [/(?:api[_-]?key|apikey|api_key)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?/gi, "API_KEY_FORMAT"],
  [/(?:secret[_-]?key|secretkey|secret_key)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?/gi, "SECRET_KEY_FORMAT"],
  [/(?:access[_-]?key|accesskey|access_key)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?/gi, "ACCESS_KEY_FORMAT"],
  [/(?:auth[_-]?token|client[_-]?secret|private[_-]?key)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{20,}['"]?/gi, "AUTH_SECRET_FORMAT"],

  // === PRIVATE KEYS ===
  [/-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|EC\s+PRIVATE)\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?(?:PRIVATE|EC\s+PRIVATE)\s+KEY-----/gi, "PRIVATE_KEY"],
  [/-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----/gi, "SSH_PRIVATE_KEY"],
  [/-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----[\s\S]*?-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/gi, "PGP_PRIVATE_KEY"],

  // === GENERIC FALLBACKS (order matters — these are last resort) ===
  [/['"][A-Za-z0-9]{20,}['"]/g, "QUOTED_SECRET"],
  [/\b[A-Za-z0-9]{40,}\b/g, "LONG_RANDOM_STRING"],
  [/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, "BASE64_SECRET"]
];
