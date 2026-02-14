<p align="center">
  <img src="icons/icon-128.png" width="96" alt="Secret Sanitizer Logo" />
</p>

<h1 align="center">Secret Sanitizer</h1>

<p align="center">
  <strong>Masks secrets before they reach AI chats. 100% local. Open source.</strong>
</p>

<p align="center">
  <a href="https://chromewebstore.google.com/detail/secret-sanitizer/genolcmpopiemhpbdnhkaefllchgekja" target="_blank">
    <img src="https://developer.chrome.com/static/docs/webstore/branding/image/iNEddTyWiMfLSwFD6qGq.png" alt="Available in the Chrome Web Store" height="58"/>
  </a>
</p>

<p align="center">
  <a href="https://github.com/souvikghosh957/secret-sanitizer-extension/stargazers">
    <img src="https://img.shields.io/github/stars/souvikghosh957/secret-sanitizer-extension?style=social" alt="GitHub Stars"/>
  </a>
  <a href="https://x.com/souvik_ghosh975">
    <img src="https://img.shields.io/twitter/follow/souvik_ghosh975?style=social&logo=x" alt="Follow on X"/>
  </a>
  <a href="https://github.com/souvikghosh957/secret-sanitizer-extension/releases">
    <img src="https://img.shields.io/github/v/release/souvikghosh957/secret-sanitizer-extension?label=Latest%20release" alt="Latest release"/>
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License"/>
  </a>
</p>

---

<p align="center">
  <img src="https://github.com/user-attachments/assets/9dc1eeb6-55a4-4be2-8a93-c21709b32469" width="720" alt="Secret Sanitizer demo — paste an API key into ChatGPT and watch it get masked instantly" />
</p>

<p align="center">
  Paste code with secrets into ChatGPT → secrets get replaced with <code>[MASKED]</code> before the message is sent → originals stay safe in your local vault. That's it.
</p>

---

### Why This Exists

In late 2025, researchers discovered that [Chrome extensions with millions of users](https://www.malwarebytes.com/blog/news/2025/12/chrome-extension-slurps-up-ai-chats-after-users-installed-it-for-privacy) — including some with Google's "Featured" badge — were **silently harvesting every AI conversation** and selling the data to brokers. The attack vector has been dubbed [**Prompt Poaching**](https://thehackernews.com/2026/01/two-chrome-extensions-caught-stealing.html).

Meanwhile, developers paste API keys, database URLs, and credentials into AI chats every day. Once sent, that data is logged — often permanently.

**Secret Sanitizer works the opposite way.** It intercepts your paste, masks anything sensitive using local regex matching, and never makes a single network request. Zero servers. Zero tracking. Fully auditable — you're reading the source right now.

---

### How It Works

```
You copy:       DATABASE_URL=postgres://admin:s3cret@db.prod.internal:5432/myapp
You paste:      DATABASE_URL=[MASKED]
Vault stores:   postgres://admin:s3cret@db.prod.internal:5432/myapp (local, encrypted)
```

1. You paste text into a supported AI chat
2. The content script intercepts the paste event **before** it hits the input field
3. Regex patterns run **locally in your browser** — no data leaves your machine
4. Detected secrets are replaced with `[MASKED]`
5. A toast notification confirms what was blocked
6. Originals are stored in a local encrypted vault you can access anytime

**No servers. No fetch calls. No analytics. `grep -r "fetch\|XMLHttpRequest\|sendMessage" content_script.js` — go ahead, check.**

---

### Supported Patterns

| Category | Examples |
|----------|----------|
| **API Keys** | AWS, GCP, Azure, Stripe, GitHub, GitLab, Slack, Twilio, SendGrid, OpenAI, and more |
| **Credentials** | Passwords, bearer tokens, basic auth headers, JWTs, OAuth tokens |
| **Database URLs** | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| **Private Keys** | RSA, SSH, PGP private key blocks |
| **Cloud & Infra** | AWS Account IDs, ARNs, S3 URLs, Docker registry credentials |
| **Indian PII** | Aadhaar numbers, PAN card numbers |
| **Other** | Generic high-entropy secrets, Base64-encoded credentials, `.env` style key-value pairs |

> 💡 **Toggle individual patterns on/off** from the extension popup. No false-positive headaches.

---

### Works On

Out-of-the-box protection for all major AI platforms:

| Platform | Status |
|----------|--------|
| ChatGPT | ✅ |
| Claude | ✅ |
| Gemini | ✅ |
| Grok | ✅ |
| Perplexity | ✅ |
| DeepSeek | ✅ |
| **Any custom site** | ✅ Add with one click |

---

### Features

- **Instant paste interception** — secrets never reach the chat input
- **Encrypted local vault** — safely review and unmask originals when needed
- **Test Mode** — preview what would get masked before committing
- **Stats dashboard** — track blocks per day, per pattern, with history
- **Custom site support** — protect any domain with one-click permission setup
- **Granular pattern controls** — enable/disable individual detection patterns
- **Backup & restore** — export/import your configuration
- **Dark mode** + keyboard shortcuts
- **38 KB total** — lightweight, no bloat

---

### Screenshots

<p align="center">
  <img width="900" alt="Instant feedback when a secret is detected and masked" src="https://github.com/user-attachments/assets/bd44237c-8e5f-4480-8aa9-6e10bb07b1b0" />
  <br><em>Instant feedback when a secret is detected and masked</em>
</p>

<p align="center">
  <img width="900" alt="Clean, animated popup with intuitive controls" src="https://github.com/user-attachments/assets/c0d21a79-7345-475c-bb98-17334625c6ba" />
  <br><em>Clean, animated popup with intuitive controls</em>
</p>

<p align="center">
  <img width="900" alt="Secure vault with one-click unmask" src="https://github.com/user-attachments/assets/54e0bc4e-a02f-43f6-8693-f033528fec98" />
  <br><em>One-click unmask from the secure local vault</em>
</p>

<p align="center">
  <img width="900" alt="Stats dashboard and settings" src="https://github.com/user-attachments/assets/f52a86e3-8b6e-4edf-8b6a-aaf33f06422a" />
  <br><em>Stats, custom sites, pattern controls, and configuration export</em>
</p>

---

### Installation

**Recommended** → [Chrome Web Store](https://chromewebstore.google.com/detail/secret-sanitizer/genolcmpopiemhpbdnhkaefllchgekja)
One-click install with automatic updates.

**Developer / Sideloading**
```bash
git clone https://github.com/souvikghosh957/secret-sanitizer-extension.git
cd secret-sanitizer-extension
```
1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the cloned folder

---

### Privacy & Security

| Claim | Verification |
|-------|-------------|
| No network requests | `grep -r "fetch\|XMLHttpRequest" content_script.js` → zero results |
| No tracking / analytics | No Google Analytics, no Mixpanel, no telemetry of any kind |
| No remote code | All pattern matching is local regex — inspect `content_script.js` |
| Works offline | Disable Wi-Fi and try it. It works. |
| Open source | You're reading it. MIT licensed. |

---

### Contributing

Contributions are welcome! Some ideas:

- **Add new secret patterns** — know a format we're missing? Open a PR
- **Report false positives** — help us fine-tune detection
- **Request platform support** — want a new AI chat site added?
- **Improve docs** — better examples, translations, etc.

Please open an issue first for larger changes so we can discuss the approach.

---

### Roadmap

- [ ] Firefox support
- [ ] Smart restore — auto-restore secrets when copying AI responses
- [ ] Pattern sharing — community-contributed pattern packs
- [ ] VS Code extension variant

---

### Star History

If this tool has saved you from a secret leak, consider giving it a ⭐ — it helps others find it.

<p align="center">
  <a href="https://github.com/souvikghosh957/secret-sanitizer-extension/stargazers">
    <img src="https://img.shields.io/github/stars/souvikghosh957/secret-sanitizer-extension?style=for-the-badge&color=yellow" alt="Star this repo"/>
  </a>
</p>

---

### License

[MIT](LICENSE) — use it, fork it, improve it.

---

<p align="center">
  Built with care by <a href="https://x.com/souvik_ghosh975">@souvik_ghosh975</a>
</p>
