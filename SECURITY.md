# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Secret Sanitizer, **please do not open a public GitHub issue.**

Instead, report it privately:

- **Email:** Reach out via [X DM (@souvik_ghosh975)](https://x.com/souvik_ghosh975) to coordinate a private channel
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
| **Zero network requests** | No fetch or XMLHttpRequest anywhere; messages only travel between the extension's own components. Verify: `grep -rn "fetch\|XMLHttpRequest" *.js popup/*.js` |
| **Local-only processing** | All pattern matching runs in your browser via regex |
| **Memory-only vault** | Originals live in `chrome.storage.session`: held in memory, never written to disk, deleted after 15 minutes or when the browser closes. Only the background worker and popup can read it; content scripts can only resolve placeholders created on their own site |
| **Page isolation** | Paste interception runs before any page script. Smart Restore writes to the clipboard from the extension's isolated world only after a trusted user gesture — plaintext is never exposed to the page's DOM or JavaScript |
| **No tracking** | No analytics, telemetry, or third-party scripts |
| **Minimal permissions** | Only requests permissions strictly needed for functionality |
| **Open source** | Full source code is auditable on GitHub |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.3.x   | Yes       |
| < 2.3   | No — earlier versions stored the vault on disk and exposed Smart Restore results to page scripts |

We recommend always using the latest version from the [Chrome Web Store](https://chromewebstore.google.com/detail/secret-sanitizer/genolcmpopiemhpbdnhkaefllchgekja).

## Known Limitations

- **Pattern-based detection is not exhaustive.** Custom or unusual secret formats may not be caught. Users can add patterns or request new ones via GitHub issues.
- **Vault entries expire after 15 minutes** by default. Secrets pasted earlier cannot be unmasked.
- **Smart Restore places originals on the system clipboard.** Anything that can read your clipboard (clipboard managers, sites you granted clipboard-read) can see them. Smart Restore turns itself off on sites that have clipboard-read permission.
- **Very large pastes (over 500 KB)** are only checked for known key formats; the toast says "partial scan" when this happens.
- **High-entropy detection may cause false positives** on long random strings that aren't secrets. Individual patterns can be disabled in settings.
