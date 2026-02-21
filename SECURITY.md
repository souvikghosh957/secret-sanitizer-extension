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
| **Zero network requests** | No fetch, XMLHttpRequest, or sendMessage calls. Verify: `grep -r "fetch\|XMLHttpRequest" content_script.js` |
| **Local-only processing** | All pattern matching runs in your browser via regex |
| **Encrypted vault** | Secrets stored with AES-GCM encryption (PBKDF2, 100K iterations) |
| **No tracking** | No analytics, telemetry, or third-party scripts |
| **Minimal permissions** | Only requests permissions strictly needed for functionality |
| **Open source** | Full source code is auditable on GitHub |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.1.x   | Yes       |
| < 2.1   | No        |

We recommend always using the latest version from the [Chrome Web Store](https://chromewebstore.google.com/detail/secret-sanitizer/genolcmpopiemhpbdnhkaefllchgekja).

## Known Limitations

- **Pattern-based detection is not exhaustive.** Custom or unusual secret formats may not be caught. Users can add patterns or request new ones via GitHub issues.
- **Vault entries expire after 15 minutes** by default. Secrets pasted earlier cannot be unmasked.
- **High-entropy detection may cause false positives** on long random strings that aren't secrets. Individual patterns can be disabled in settings.
