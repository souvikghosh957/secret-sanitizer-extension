# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Secret Sanitizer, **please do not open a public GitHub issue.**

Instead, report it privately:

- **Contact:** Reach out via [X DM (@souvik_ghosh975)](https://x.com/souvik_ghosh975) to coordinate a private channel
- **Subject:** Include "Secret Sanitizer Security" in your message

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Assessment:** Within 1 week
- **Fix:** As soon as possible, depending on severity

## Security Design

Secret Sanitizer is built with a security-first architecture:

| Principle | Implementation |
|-----------|---------------|
| **Zero network requests** | No fetch or XMLHttpRequest anywhere; messages only travel between the extension's own components. Verify: `grep -n "fetch\|XMLHttpRequest" *.js popup/*.js`. The only web page involved is the static uninstall page Chrome opens after removal, which has no scripts and receives nothing about you |
| **Local-only processing** | All pattern matching runs in your browser via regex |
| **Memory-only vault** | Originals live in `chrome.storage.session`: held in memory, never written to disk, deleted after 15 minutes or when the browser closes. Only the background worker and popup can read it; content scripts can only resolve placeholders created on their own site |
| **Page isolation** | Paste interception runs before any page script. Smart Restore writes to the clipboard from the extension's isolated world only after a trusted copy gesture (a click outside a text field, a copy shortcut, or right-click → Copy; typing doesn't count) — plaintext is never exposed to the page's DOM or JavaScript |
| **No tracking** | No analytics, telemetry, or third-party scripts |
| **Minimal permissions** | Only requests permissions strictly needed for functionality |
| **Open source** | Full source code is auditable on GitHub |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.4.x   | Yes       |
| 2.3.x   | No — please update |
| < 2.3   | No — earlier versions stored the vault on disk and exposed Smart Restore results to page scripts |

We recommend always using the latest version from the [Chrome Web Store](https://chromewebstore.google.com/detail/secret-sanitizer/genolcmpopiemhpbdnhkaefllchgekja).

## Known Limitations

- **Pattern-based detection is not exhaustive.** Custom or unusual secret formats may not be caught. New patterns can be requested via GitHub issues.
- **Vault entries expire after 15 minutes** by default. Secrets pasted earlier cannot be unmasked.
- **Smart Restore places originals on the system clipboard.** Anything that can read your clipboard (clipboard managers, sites you granted clipboard-read) can see them. Smart Restore turns itself off on sites that have clipboard-read permission and while masking is paused.
- **Very large pastes (over 500 KB)** are only checked for known key formats; the toast says "partial scan" when this happens.
- **Random-token detection is a best guess.** It can mask a random-looking value that isn't secret: use "Not a secret?" on the toast or turn the rule off. It also skips URL hosts and paths and content hashes, so a secret with no recognised format inside a URL path (a custom webhook, say) isn't masked.
- **Pausing turns masking off.** While paused, for 10 minutes or on one site, pastes reach the page unchanged and copying keeps placeholders instead of restoring originals. The toolbar badge shows `OFF`.
- **Allowed values stay unmasked** until you clear them in Settings. This applies only to guessing rules; recognised key formats are always masked.
