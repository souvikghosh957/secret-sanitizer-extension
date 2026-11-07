// One-line example for each detection rule, shown under its toggle. Rule names are translated
// (_locales: pattern_<LABEL>); examples are code, so they aren't. Deliberately truncated:
// nothing here should itself look like a usable credential.
const PATTERN_EXAMPLES = {
  AWS_KEY: "AKIA…", AWS_TEMP_KEY: "ASIA…", AZURE_SECRET: "tenant_id = 12ab…-…", GOOGLE_API_KEY: "AIza…",
  GITHUB_TOKEN: "ghp_…", GITHUB_FINE_PAT: "github_pat_…", GITLAB_TOKEN: "glpat-…", GITLAB_TRIGGER_TOKEN: "glptt-…",
  JWT: "eyJ….eyJ….…", DB_CONN: "postgres://user:pass@host/db", URL_CREDENTIALS: "https://user:token@host",
  CREDIT_CARD: "4111 1111 1111 …",
  STRIPE_KEY: "sk_live_…", STRIPE_TEST_KEY: "sk_test_…", STRIPE_PUB_KEY: "pk_live_…", STRIPE_TEST_PUB_KEY: "pk_test_…",
  SQUARE_ACCESS_TOKEN: "sq0atp-…", SQUARE_SECRET: "sq0csp-…", RAZORPAY_KEY: "rzp_live_…", RAZORPAY_TEST_KEY: "rzp_test_…",
  PAYTM_KEY: "paytm_key = …", PAYTM_MERCHANT: "merchant_key = …",
  TWILIO_SID: "AC0123…", TWILIO_AUTH_TOKEN: "auth_token = …", SLACK_TOKEN: "xoxb-…",
  SLACK_WEBHOOK: "https://hooks.slack.com/services/…", TEAMS_WEBHOOK: "https://….webhook.office.com/…",
  DISCORD_WEBHOOK: "https://discord.com/api/webhooks/…", TELEGRAM_BOT_TOKEN: "123456789:AA…",
  SENDGRID_KEY: "SG.….…", MAILGUN_KEY: "mailgun = key-…",
  ANTHROPIC_KEY: "sk-ant-…", OPENAI_KEY: "sk-proj-…", GROQ_KEY: "gsk_…", HUGGINGFACE_TOKEN: "hf_…",
  FIREBASE_KEY: "AAAA…:…", HEROKU_API_KEY: "HEROKU_API_KEY = …", VERCEL_TOKEN: "vcp_…",
  DIGITALOCEAN_TOKEN: "dop_v1_…", DIGITALOCEAN_REFRESH: "doctl-…", SUPABASE_TOKEN: "sbp_…",
  CLOUDFLARE_TOKEN: "CF_API_TOKEN = …", DATADOG_KEY: "dd_api_key = …", SHOPIFY_TOKEN: "shpat_…",
  NPM_TOKEN: "npm_…", PYPI_TOKEN: "pypi-…",
  AADHAAR: "2341 2341 ….", PAN: "ABCPE1234F", INDIAN_PHONE: "+91 98765…", GSTIN: "22ABCDE1234F1Z5", IFSC: "IFSC: SBIN0005943",
  UPI_ID: "name@oksbi", UPI_ID_GENERIC: "name@upi", UPI_TEST_ID: "success@razorpay", PAYMENT_UPI_ID: "name@paytm",
  DRIVING_LICENSE: "MH12 2011 …", VOTER_ID: "voter id: ABC1234567", PASSPORT: "passport: A1234567", VEHICLE_REG: "vehicle: MH12AB1234",
  OTP_CODE: "Your OTP is 482910", EMAIL_IN_SECRET: "password: me@example.com", PASSWORD_HINT: "password: hunter2",
  BEARER_TOKEN: "Bearer Zq8x…", BASIC_AUTH: "Authorization: Basic dXNlcj…",
  API_KEY_FORMAT: "api_key = …", SECRET_KEY_FORMAT: "secret_key = …", ACCESS_KEY_FORMAT: "access_key = …", AUTH_SECRET_FORMAT: "client_secret = …",
  PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----", SSH_PRIVATE_KEY: "-----BEGIN OPENSSH PRIVATE KEY-----", PGP_PRIVATE_KEY: "-----BEGIN PGP PRIVATE KEY BLOCK-----",
  QUOTED_SECRET: "\"Zq8xW3vR7tY2uI9oP4aS\"", LONG_RANDOM_STRING: "9fQ2xLm7…(40+ characters)", BASE64_SECRET: "wJalr/K7MD…(40+ characters)", ENTROPY: "Zq8xW3vR7tY2uI9o"
};
