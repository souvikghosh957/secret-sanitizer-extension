# Changelog

All notable changes to Secret Sanitizer are documented here.

## [2.1.3] - 2026-03-06

### Fixed
- XSS hardening: replaced all innerHTML with DOM construction (createElement + textContent)
- ContentEditable paste fix: execCommand-first approach prevents wiping editor state in ChatGPT/Claude/Gemini
- Race condition: debounced content script registration on rapid site toggles
- Patterns available immediately on load (sync init instead of waiting for async)
- Ctrl+D no longer triggers double confirmation dialog
- DPI scaling fix now targets Windows only (was applying to Linux/ChromeOS)
- Action button double-click guard uses synchronous disabled property
- Array validation before iterating decrypted vault replacements
- Removed unused `request.total` argument in milestone celebration call

### Changed
- Unified site chip design: default and custom sites rendered as consistent chips
- Enter key now works in custom site input field
- Alarm creation moved to onInstalled (no longer recreated on every service worker wake)
- Removed unused `activeTab` permission
- Removed Perplexity and DeepSeek from default sites documentation (available as custom sites)

## [2.1.2] - 2026-03-01

### Added
- 20+ new secret detection patterns: Slack, GitLab, Discord webhook, Telegram bot, SendGrid, Anthropic, HuggingFace, Square, Vercel, DigitalOcean, Supabase, Shopify, PyPI, SSH (OPENSSH) private keys, GitHub fine-grained PATs, and more
- Contextual detection for Azure, Heroku, Datadog, Cloudflare, and Mailgun (requires keyword proximity to avoid false positives)
- `AUTH_SECRET_FORMAT` pattern for `auth_token=`, `client_secret=`, `private_key=` env vars
- AMQP/AMQPS protocol support in database connection detection

### Fixed
- OpenAI/Anthropic key mislabeling — `sk-ant-*` keys no longer detected as OpenAI
- `quickCheck` fast-path now covers all new pattern prefixes (was silently skipping new patterns on short pastes)
- Welcome page demo key updated to realistic Stripe example that actually triggers detection in test mode

### Removed
- Overly broad patterns that caused false positives: `AWS_SECRET_KEY` (matched any 40-char string), `BANK_ACCOUNT` (matched any 9-18 digit number), bare `MAILGUN_KEY`, `GENERIC_SECRET_KEY` (unreachable), `NUGET_KEY` (unverified prefix)
- Duplicate `RAZORPAY_TEST_SECRET` pattern (already caught by `RAZORPAY_TEST_KEY`)

### Changed
- Groq key label corrected from `GROK_KEY` to `GROQ_KEY`
- Slack token detection now includes `xoxe-` (expiring tokens)
- Shopify token charset fixed from hex-only to full alphanumeric, added `shpua_` prefix
- PyPI token minimum length raised from 16 to 50 to reduce false positives
- Vercel token prefix corrected from `vercel_` to `vc[pcirka]_`
- Pattern list reorganized: specific prefixed patterns first, contextual second, generic fallbacks last

## [2.1.0] - 2026-02-18

### Fixed
- Bug fixes for Chrome Web Store release

### Changed
- Improved stability and reliability

## [2.0.5] - 2026-02-18

### Changed
- Redesigned popup with dark luxury premium theme
- Updated visual design for a premium security dashboard feel

## [2.0.4] - 2026-02-13

### Fixed
- Fixed browsing history permission issue
- Fixed sites accordion toggling closed when navigating from status bar

### Changed
- Made welcome page feature points non-interactive

## [2.0.3] - 2026-02-10

### Added
- Smart toast notifications with undo functionality
- Welcome screen for first-time users
- Site status indicator in popup
- Weekly summary and milestone celebrations (100, 500, 1K, 5K, 10K, 50K, 100K secrets protected)

### Removed
- Context menu integration (simplified UX)

## [2.0.2] - 2026-02-06

### Fixed
- Improved short message check for Indian PII patterns

## [2.0.1] - 2026-01-27

### Changed
- Redesigned popup UI with hero stats and unified action area

## [2.0.0] - 2026-01-23

### Added
- Encrypted local vault (AES-GCM with PBKDF2)
- Test mode for previewing what gets masked
- Stats dashboard with per-day and per-pattern tracking
- Custom site support with one-click permission setup
- Granular pattern controls (enable/disable individual patterns)
- Backup and restore configuration
- Dark mode with system preference detection
- Keyboard shortcuts (Ctrl+Enter to analyze, Ctrl+D to delete all)

### Changed
- Complete rewrite of popup UI
- Improved pattern matching with entropy-based detection
- Better false positive handling

## [1.0.0] - 2026-01-17

### Added
- Initial release
- Basic paste interception on AI chat platforms
- Regex-based secret detection (API keys, passwords, tokens, database URLs, private keys)
- Toast notification on secret detection
- Support for ChatGPT, Claude, Gemini, Grok
