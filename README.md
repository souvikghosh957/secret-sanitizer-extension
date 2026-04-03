<p align="center">
  <img src="readme-heading.png" width="800" alt="Secret Sanitizer — Prevent API Key & Credential Leaks to AI Chats" />
</p>

<p align="center">
  <b>Masks API keys, passwords & tokens before they reach AI chats — 100% local, open source, zero tracking.</b>
</p>

<p align="center">
  <a href="#the-problem">The Problem</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#supported-platforms">Platforms</a> &bull;
  <a href="#what-it-catches">Detection</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#screenshots">Screenshots</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#privacy--security">Privacy</a>
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
  <a href="https://secretsanitizer.com">
    <img src="https://img.shields.io/badge/Website-secretsanitizer.com-0ea5e9?style=flat-square&logo=google-chrome&logoColor=white" alt="Website"/>
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
| **7** | ✨ **Smart Restore** — copy any AI response containing placeholders and the originals are automatically put back in your clipboard |

> **Don't take our word for it.** Run `grep -r "fetch\|XMLHttpRequest" content_script.js` — zero results.

---

## Supported Platforms

Works out of the box on every major AI chat:

| ChatGPT | Claude | Gemini | Grok | Custom Sites |
|:-------:|:------:|:------:|:----:|:------------:|
| &check; | &check; | &check; | &check; | &check; One-click add |

---

## What It Catches

<table>
<tr>
<td width="50%">

**Credentials & Tokens**
- Passwords & password hints
- Bearer tokens & JWTs
- OTP codes & PINs
- OAuth tokens & refresh tokens

**API Keys & Platforms**
- AWS, Google Cloud, Azure
- OpenAI, Anthropic, Groq, HuggingFace
- Stripe, Square, Razorpay, Paytm
- GitHub, GitLab (PATs & trigger tokens)
- Slack, Twilio, SendGrid, Mailgun
- Discord webhooks, Telegram bot tokens

</td>
<td width="50%">

**Infrastructure & Cloud**
- PostgreSQL, MySQL, MongoDB, Redis, RabbitMQ URLs
- Firebase, Vercel, DigitalOcean, Supabase
- Heroku, Cloudflare, Datadog (contextual)
- Shopify, NPM, PyPI tokens
- `.env` key-value pairs (`API_KEY=`, `SECRET_KEY=`, etc.)

**Private Data**
- RSA, SSH (OpenSSH), PGP private key blocks
- Aadhaar, PAN, GSTIN, UPI IDs
- Credit card numbers
- High-entropy & base64-encoded secrets

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
<td align="center" width="25%"><strong>Smart Restore</strong><br><sub>Copy AI responses — secrets auto-restored in clipboard</sub></td>
<td align="center" width="25%"><strong>Scan Feedback</strong><br><sub>Toast on every paste — clean or caught</sub></td>
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
<td align="center"><strong>Interactive Demos</strong><br><sub>Try it with sample secrets instantly</sub></td>
<td align="center"><strong>Lightweight &amp; Fast</strong><br><sub>Zero dependencies, minimal footprint, optimized for speed</sub></td>
</tr>
</table>

---

## Screenshots

<p align="center">
  <img width="720" alt="Instant feedback when a secret is detected and masked" src="https://github.com/user-attachments/assets/53c82a0b-75d0-467c-bd49-322ad0eab5d5" />
  <br><em>Instant feedback when a secret is detected and masked</em>
</p>

<p align="center">
  <img width="720" alt="Clean, animated popup with intuitive controls" src="https://github.com/user-attachments/assets/3ce4f70e-d33a-4af4-904f-1e2888da6b35" />
  <br><em>Clean, animated popup with intuitive controls</em>
</p>

<p align="center">
  <img width="720" alt="Custom sites, pattern controls, and configuration export" src="https://github.com/user-attachments/assets/270e6b89-0e73-4e6f-ae8a-bbe2a7e56db7" />
  <br><em>Custom sites, pattern controls, and configuration export</em>
</p>

<p align="center">
  <img width="720" alt="One-click unmask from the secure local vault" src="https://github.com/user-attachments/assets/72d03545-0ed8-4737-8d99-bc6f109439ad" />
  <br><em>One-click unmask from the secure local vault</em>
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
- [x] Smart Restore — auto-restore secrets when copying AI responses
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

<p align="center">
  <br>If Secret Sanitizer has saved you from a secret leak, consider giving it a star — it helps others find it.
</p>

<p align="center">
  <a href="https://github.com/souvikghosh957/secret-sanitizer-extension/stargazers">
    <img src="https://img.shields.io/github/stars/souvikghosh957/secret-sanitizer-extension?style=for-the-badge&color=yellow&logo=github" alt="Star this repo"/>
  </a>
</p>

<p align="center">
  <sub>Built with care by <a href="https://x.com/souvik_ghosh975">@souvik_ghosh975</a></sub>
</p>
