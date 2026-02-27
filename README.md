<p align="center">
  <img src="icons/icon-128.png" width="100" alt="Secret Sanitizer" />
</p>

<h1 align="center">Secret Sanitizer</h1>

<p align="center">
  <strong>Your secrets never leave your machine. Ever.</strong><br>
  <sub>Masks API keys, passwords & tokens before they reach AI chats — 100% local, open source, zero tracking.</sub>
</p>

<p align="center">
  <a href="https://chromewebstore.google.com/detail/secret-sanitizer/genolcmpopiemhpbdnhkaefllchgekja">
    <img src="https://img.shields.io/chrome-web-store/v/genolcmpopiemhpbdnhkaefllchgekja?style=flat-square&logo=googlechrome&logoColor=white&label=Chrome%20Web%20Store&color=4285F4" alt="Chrome Web Store"/>
  </a>
  <a href="https://github.com/souvikghosh957/secret-sanitizer-extension/stargazers">
    <img src="https://img.shields.io/github/stars/souvikghosh957/secret-sanitizer-extension?style=flat-square&logo=github&color=yellow" alt="GitHub Stars"/>
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License"/>
  </a>
  <a href="https://x.com/souvik_ghosh975">
    <img src="https://img.shields.io/badge/Follow-@souvik__ghosh975-black?style=flat-square&logo=x" alt="Follow on X"/>
  </a>
</p>

<p align="center">
  <a href="https://chromewebstore.google.com/detail/secret-sanitizer/genolcmpopiemhpbdnhkaefllchgekja">
    <img src="https://developer.chrome.com/static/docs/webstore/branding/image/iNEddTyWiMfLSwFD6qGq.png" alt="Available in the Chrome Web Store" height="58"/>
  </a>
</p>

---

<p align="center">
  <img src="https://github.com/user-attachments/assets/9dc1eeb6-55a4-4be2-8a93-c21709b32469" width="720" alt="Secret Sanitizer demo — paste an API key into ChatGPT and watch it get masked instantly" />
</p>

<p align="center">
  <code>Ctrl+V</code> your code into ChatGPT &rarr; secrets are replaced with <code>[MASKED]</code> before the message sends &rarr; originals stay safe in your local encrypted vault.
</p>

---

## The Problem

In December 2025, researchers discovered that [Chrome extensions with millions of users](https://www.malwarebytes.com/blog/news/2025/12/chrome-extension-slurps-up-ai-chats-after-users-installed-it-for-privacy) — including some with Google's "Featured" badge — were **silently harvesting every AI conversation** and selling the data to brokers. The attack has been dubbed [**Prompt Poaching**](https://thehackernews.com/2026/01/two-chrome-extensions-caught-stealing.html).

Meanwhile, developers paste API keys, database URLs, and credentials into AI chats every day. Once sent, that data is logged — often permanently.

**Secret Sanitizer works the opposite way.** It intercepts your paste, masks anything sensitive using local regex matching, and never makes a single network request. Zero servers. Zero tracking. Fully auditable — you're reading the source right now.

---

## How It Works

```
You copy:       DATABASE_URL=postgres://admin:s3cret@db.prod.internal:5432/myapp
You paste:      DATABASE_URL=[MASKED]
Vault stores:   postgres://admin:s3cret@db.prod.internal:5432/myapp  (local, encrypted)
```

| Step | What happens |
|:----:|-------------|
| **1** | You paste text into a supported AI chat |
| **2** | Content script intercepts the paste **before** it hits the input field |
| **3** | Regex patterns run **locally in your browser** — no data leaves your machine |
| **4** | Detected secrets are replaced with safe `[MASKED]` placeholders |
| **5** | A toast notification confirms what was blocked |
| **6** | Originals are stored in a local AES-GCM encrypted vault you can access anytime |

> **Don't take our word for it.** Run `grep -r "fetch\|XMLHttpRequest" content_script.js` — zero results.

---

## Supported Platforms

Works out of the box on every major AI chat:

<p align="center">

| ChatGPT | Claude | Gemini | Grok | Perplexity | DeepSeek | Any site |
|:-------:|:------:|:------:|:----:|:----------:|:--------:|:--------:|
| &check; | &check; | &check; | &check; | &check; | &check; | &check; Add with one click |

</p>

---

## What It Catches

<table>
<tr>
<td width="50%">

**Credentials & Tokens**
- Passwords & password hints
- Bearer tokens & JWTs
- Basic auth headers
- OAuth tokens & refresh tokens

**API Keys**
- AWS, GCP, Azure
- OpenAI, Anthropic
- Stripe, GitHub, GitLab
- Slack, Twilio, SendGrid & more

</td>
<td width="50%">

**Infrastructure**
- PostgreSQL, MySQL, MongoDB, Redis URLs
- AWS Account IDs, ARNs, S3 URLs
- Docker registry credentials
- `.env` key-value pairs

**Private Data**
- RSA, SSH, PGP private key blocks
- Aadhaar numbers, PAN cards
- High-entropy secrets
- Base64-encoded credentials

</td>
</tr>
</table>

> Toggle any pattern on/off from the popup — no false-positive headaches.

---

## Features

<table>
<tr>
<td align="center" width="25%"><strong>Instant Interception</strong><br><sub>Secrets never reach the chat input</sub></td>
<td align="center" width="25%"><strong>Encrypted Vault</strong><br><sub>AES-GCM encrypted, local only</sub></td>
<td align="center" width="25%"><strong>Scan Feedback</strong><br><sub>Toast on every paste — clean or caught</sub></td>
<td align="center" width="25%"><strong>Interactive Demos</strong><br><sub>Try it with sample secrets instantly</sub></td>
</tr>
<tr>
<td align="center"><strong>Test Mode</strong><br><sub>Preview masking before committing</sub></td>
<td align="center"><strong>Stats Dashboard</strong><br><sub>Track blocks per day with history</sub></td>
<td align="center"><strong>Pattern Controls</strong><br><sub>Enable/disable individual patterns</sub></td>
<td align="center"><strong>Custom Sites</strong><br><sub>Protect any domain, one click</sub></td>
</tr>
<tr>
<td align="center"><strong>Backup & Restore</strong><br><sub>Export/import your config as JSON</sub></td>
<td align="center"><strong>Dark Mode</strong><br><sub>Dark by default, matches your setup</sub></td>
<td align="center"><strong>Share Button</strong><br><sub>Spread the word in one click</sub></td>
<td align="center"><strong>~68 KB Total</strong><br><sub>Lightweight, no bloat, no deps</sub></td>
</tr>
</table>

---

## Screenshots

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

## Install

**One click** &rarr; [Chrome Web Store](https://chromewebstore.google.com/detail/secret-sanitizer/genolcmpopiemhpbdnhkaefllchgekja) (recommended, auto-updates)

<details>
<summary><strong>Manual / Developer install</strong></summary>

```bash
git clone https://github.com/souvikghosh957/secret-sanitizer-extension.git
cd secret-sanitizer-extension
```

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** &rarr; select the cloned folder

</details>

---

## Privacy & Security

| Claim | How to verify |
|-------|--------------|
| **No network requests** | `grep -r "fetch\|XMLHttpRequest" content_script.js` &rarr; zero results |
| **No tracking** | No Google Analytics, no Mixpanel, no telemetry of any kind |
| **No remote code** | All pattern matching is local regex — inspect `content_script.js` |
| **Works offline** | Disable Wi-Fi and try it. It works. |
| **Open source** | You're reading it right now. MIT licensed. |

---

## Roadmap

- [ ] Firefox support
- [ ] Smart restore — auto-restore secrets when copying AI responses
- [ ] Pattern sharing — community-contributed pattern packs
- [ ] VS Code extension variant

---

## Contributing

Contributions are welcome! Some ideas:

- **Add new secret patterns** — know a format we're missing? Open a PR
- **Report false positives** — help us fine-tune detection
- **Request platform support** — want a new AI chat site added?

Please open an issue first for larger changes so we can discuss the approach.

---

## License

[MIT](LICENSE) — use it, fork it, improve it.

---

<p align="center">
  If Secret Sanitizer has saved you from a secret leak, consider giving it a star — it helps others find it.
</p>

<p align="center">
  <a href="https://github.com/souvikghosh957/secret-sanitizer-extension/stargazers">
    <img src="https://img.shields.io/github/stars/souvikghosh957/secret-sanitizer-extension?style=for-the-badge&color=yellow&logo=github" alt="Star this repo"/>
  </a>
</p>

<p align="center">
  <sub>Built with care by <a href="https://x.com/souvik_ghosh975">@souvik_ghosh975</a></sub>
</p>
