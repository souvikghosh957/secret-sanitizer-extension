# Changelog

All notable changes to Secret Sanitizer are documented here.

## [2.3.0] - 2026-10-11

### Security
- **Smart Restore no longer exposes originals to the page.** Restored text used to be broadcast on a DOM `CustomEvent` (`__ss_resolved`) that any script on the AI site could read — and trigger by placing placeholders in a hidden textarea. Restored text is now written to the clipboard only from the extension's isolated world, never via DOM events or `clipboardData.setData()`, and only after a trusted user click/keypress. The MAIN-world interceptor now only relays masked text one way (page → extension)
- **Smart Restore is scoped to the originating site** — placeholders created on one site can't be resolved on another — and switches off on sites that have clipboard-read permission
- **Vault moved to memory-only storage.** The "AES-GCM encrypted" vault was keyed from the public extension ID, so anything that could read the profile could decrypt it. Originals now live in `chrome.storage.session` (never written to disk, cleared when the browser closes), accessible only to the background worker and popup. The old on-disk vault is deleted on update, and the encryption toggle is removed
- **Re-pasting restored text into the AI chat is masked again** — previously the next paste after a Smart Restore skipped masking entirely
- **Undo can't be triggered by page script** — the Undo button ignores synthetic (untrusted) clicks
- Content scripts now run at `document_start`, so the paste listener is registered before any page script can see or block the paste
- Pastes arriving before settings load are scanned with all patterns instead of being skipped

### Fixed
- **Placeholder collisions** — numbering restarted at 0 on every paste, so two different keys both became `[OPENAI_KEY_0]` and Smart Restore could return the wrong one. Placeholders now carry a per-paste id: `[OPENAI_KEY_k3f9_0]`
- **Database URLs** — `postgresql://`, `mongodb+srv://`, `rediss://`, `mariadb://`, `mssql://`, SQLAlchemy dialects and empty-user URLs are now detected
- **Credentials in any URL** (`https://user:token@host`) are now masked (password part only)
- **Secrets missed when combined** — entropy detection only ran when no pattern matched, so a `postgresql://` password next to an AWS key leaked. Entropy and generic fallbacks now fill every gap left by specific patterns
- **Large pastes** — anything over 5 KB skipped generic and entropy checks and showed nothing. Pastes up to 500 KB now get the full scan (~40 ms); larger ones still get every prefixed pattern and the toast says "partial scan". Hitting the match cap is reported the same way instead of silently skipping later patterns
- **Repeated secrets** — entropy detection only masked the first occurrence of an identical value
- **Passwords** — any characters, 6+ long (`password: hunter2`, `DB_PASSWORD=p@ss/w0rd?2024~xy`), masking only the value
- **Key names preserved** — `KEY=value` patterns and entropy matches mask only the value, so the AI keeps context; specific patterns win over generic ones (`OPENAI_API_KEY=[OPENAI_KEY_…]`)
- **False positives** — Luhn check for cards, Verhoeff check for Aadhaar, no Aadhaar match on UUID tails, no OTP match on "exit code 1234", git SHAs, long identifiers and file paths, `PWD=/path`, `password: string`, `password = getenv(...)`
- **One bad custom site disabled protection everywhere** — default and custom sites are now registered separately, and sites are validated on add and on import
- **Weekly summary dates** — `getWeekStart` produced dates like `2026-10--3` when a week spanned two months
- **Bearer tokens** — `Bearer <JWT>` is labelled `JWT` and the `Bearer` keyword stays readable
- **Stale "Today" count** — the popup and toolbar badge showed yesterday's count until the first paste of a new day
- Pattern toggles apply to open tabs immediately; custom sites with a port now match correctly

### Changed
- Detection engine extracted to `detector.js`, shared by the content script, the popup test mode and the new test suite — the popup's separate copy of the engine and the three copies of the crypto code are gone
- Stats are updated by the background worker (single writer, no cross-tab races)
- Popup **Recent** list shows the site each paste came from
- Added a dependency-free test suite (`node --test 'tests/*.test.js'`) and a GitHub Actions workflow
- `minimum_chrome_version` set to 102 (required by `chrome.storage.session` and MAIN-world content scripts)
- Website and privacy policy updated: memory-only vault, new placeholder format, accurate demo, supported sites and stats wording

## [2.2.7] - 2026-04-10

### Fixed
- **Unmask broken in popup** — `regex.test()` on a `g`-flag regex advances `lastIndex`, causing the subsequent `.replace()` to skip the match entirely. Switched to a replacer function; also fixes secrets containing `$` characters (e.g. `P@$$w0rd`) being silently corrupted by `String.replace()` special `$` patterns
- **Alarms lost after browser restart** — `vaultCleanup` and `weeklySummary` alarms were only created on `onInstalled`. MV3 service workers can be killed at any time; alarms are now checked and re-created on `onStartup` if missing
- **Weekly summary wrong day for non-UTC users** — `getWeekStart` used `toISOString()` (always UTC) after setting local midnight, shifting the date by a day for users west of UTC. Now uses local date arithmetic throughout
- **`document.body` null crash in clipboard interceptor** — `triggerCopyEvent` called `document.body.appendChild` at `document_start` where `body` can be null on some pages; added null guard
- **Settings import not restoring `removedDefaults`** — export included this key but import silently dropped it, so removed default sites were lost on backup/restore
- Settings export now includes all keys — `autoDarkMode` and `darkMode` were handled by import but missing from export
- "Delete All Secrets" button now uses `createElement`/`textContent` instead of `innerHTML`
- Review toast icon gracefully hides on custom sites outside `web_accessible_resources`
- Message handler in content script returns `false` for synchronous responses (was incorrectly `true`)

### Changed
- Added `short_name: "Secret Sanitizer"` to manifest
- Updated manifest description — shorter and more direct
- README vault TTL corrected from "24 hours" to "15 minutes"
- CONTRIBUTING.md updated to current pattern format and file structure

## [2.2.5] - 2026-03-24

### Fixed
- Settings import now rejects files larger than 100 KB to prevent memory exhaustion from malicious files
- Custom site input now validates that only `http://` and `https://` URLs are accepted — blocks `chrome://`, `javascript:`, and other unsafe protocols
- Milestone and review toasts no longer overlap — stacking offset now accounts for all visible extension toasts
- Silent `catch` blocks replaced with `console.warn` or explanatory comments for easier debugging

### Changed
- Standardized regex flags to `/gi` across all token detection patterns for consistent case-insensitive matching (JWT, CREDIT_CARD, AADHAAR, PAN, and generic fallbacks intentionally kept as `/g`)
- Pattern toggle labels derived directly from `SHARED_PATTERNS` — eliminates manual sync risk when new patterns are added
- Updated Chrome Web Store title and short description for better visibility and search relevance

## [2.2.0] - 2026-03-07

### Fixed
- `dismissTimeout` variable ordering in smart toast — declared before undo button closure that references it
- Stale vault timer display — `minsLeft` now uses live `Date.now()` instead of captured startup value
- Missing `VERCEL_TOKEN` guard in pattern fast-filter — regex was running unnecessarily on every paste
- Background message handler returns `false` for unknown senders to properly close message port
- `.DS_Store` files and old release `.zip` files removed from git tracking

### Changed
- **False positive reduction**: `INDIAN_PHONE`, `VOTER_ID`, `PASSPORT`, and `VEHICLE_REG` patterns now require keyword context (e.g., `+91`, `phone:`, `passport no:`) instead of matching bare numbers/codes
- **Pattern deduplication**: all 50+ detection patterns moved to shared `patterns.js` — single source of truth for both content script and popup test mode (eliminates drift risk)
- Quick-check fast path updated to cover Vercel token prefix and contextual pattern keywords
- Added explicit Content Security Policy (`script-src 'self'`) to manifest.json

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
