<p align="center">
  <img src="readme-heading.png" alt="Secret Sanitizer — Prevent API Key & Credential Leaks to AI Chats" style="max-width:100%;" />
</p>

<p align="center">
  Masks your secrets before they reach AI chats — 100% local, open source, zero tracking.
</p>

<p align="center">
  <a href="#the-problem">The Problem</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#smart-restore">Smart Restore</a> &bull;
  <a href="#supported-platforms">Platforms</a> &bull;
  <a href="#what-it-catches">What It Catches</a> &bull;
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
  <img src="https://github.com/user-attachments/assets/9dc1eeb6-55a4-4be2-8a93-c21709b32469" width="720" alt="Secret Sanitizer demo" />
</p>

<p align="center">
  Paste your code &rarr; secrets become <code>[MASKED]</code> &rarr; originals stay safe on your machine.
</p>

---

## The Problem

Developers paste API keys, database passwords, and credentials into AI chats every day — often without thinking twice. Once sent, that data is logged by the AI service, sometimes permanently.

On top of that, [researchers found in late 2025](https://www.malwarebytes.com/blog/news/2025/12/chrome-extension-slurps-up-ai-chats-after-users-installed-it-for-privacy) that popular Chrome extensions were silently reading and selling AI conversations, including some with Google's "Featured" badge.

Secret Sanitizer flips this: it catches secrets **before** they leave your machine, replaces them with safe placeholders, and never touches a server. You can verify that yourself — you're reading the source right now.

---

## How It Works

```
You paste:    DATABASE_URL=postgres://admin:s3cret@db.prod.internal:5432/myapp
AI receives:  DATABASE_URL=[DATABASE_URL_0]
Vault stores: postgres://admin:s3cret@db.prod.internal:5432/myapp  ← local only
```

1. You paste text into an AI chat
2. The extension intercepts it before it hits the input field
3. Patterns run locally in your browser — nothing leaves your machine
4. Secrets are swapped with readable placeholders like `[STRIPE_KEY_0]`
5. A toast notification shows what was caught, with a 5-second undo
6. Originals are stored in a local AES-GCM encrypted vault

> **Verify it yourself:** `grep -r "fetch\|XMLHttpRequest" content_script.js` — zero results.

---

## Smart Restore

When the AI replies using your placeholders, you get the real values back automatically.

**Example:**

1. You ask: *"Fix this connection string: `[DATABASE_URL_0]`"*
2. AI replies: *"Change `[DATABASE_URL_0]` to use port 5433."*
3. You copy the reply — Secret Sanitizer detects the placeholders and swaps them back to the originals in your clipboard instantly.

No manual lookup. No digging through the vault. Just paste and it works.

Originals are kept for 24 hours and are always accessible from the popup under **Recent**.

---

## Supported Platforms

Works out of the box on every major AI chat:

| ChatGPT | Claude | Gemini | Grok | Custom Sites |
|:-------:|:------:|:------:|:----:|:------------:|
| ✓ | ✓ | ✓ | ✓ | ✓ One-click add |

---

## What It Catches

**Credentials & Tokens**
- Passwords, bearer tokens, JWTs
- OTP codes, PINs, OAuth & refresh tokens

**API Keys**
- AWS, Google Cloud, Azure
- OpenAI, Anthropic, Groq, HuggingFace
- Stripe, Square, Razorpay, Paytm
- GitHub, GitLab (personal access tokens)
- Slack, Twilio, SendGrid, Mailgun
- Discord webhooks, Telegram bot tokens

**Infrastructure**
- PostgreSQL, MySQL, MongoDB, Redis, RabbitMQ connection URLs
- Firebase, Vercel, DigitalOcean, Supabase, Heroku, Cloudflare
- Shopify, NPM, PyPI tokens
- `.env` key-value pairs

**Private & Sensitive Data**
- RSA, SSH, PGP private keys
- Aadhaar, PAN, GSTIN, UPI IDs
- Credit card numbers
- High-entropy and base64-encoded secrets

> Toggle any pattern on or off from the popup to avoid false positives.

---

## Features

| | |
|---|---|
| **Instant interception** | Secrets never reach the chat input |
| **Encrypted vault** | AES-GCM encrypted, stored locally only |
| **Smart Restore** | Copy AI responses and secrets auto-restore in your clipboard |
| **Undo on paste** | 5-second window to revert any masked paste |
| **Test mode** | Preview what would be masked before committing |
| **Pattern controls** | Enable or disable individual detection patterns |
| **Custom sites** | Add any domain with one click |
| **Stats dashboard** | See how many secrets were caught and when |
| **Backup & restore** | Export and import your config as JSON |
| **Dark mode** | Matches your system theme |

---

## Screenshots

<p align="center">
  <img width="720" alt="Instant feedback when a secret is detected" src="https://github.com/user-attachments/assets/53c82a0b-75d0-467c-bd49-322ad0eab5d5" />
  <br><em>Instant feedback when a secret is detected and masked</em>
</p>

<p align="center">
  <img width="720" alt="Popup with controls" src="https://github.com/user-attachments/assets/3ce4f70e-d33a-4af4-904f-1e2888da6b35" />
  <br><em>Clean popup with intuitive controls</em>
</p>

<p align="center">
  <img width="720" alt="Pattern controls and custom sites" src="https://github.com/user-attachments/assets/270e6b89-0e73-4e6f-ae8a-bbe2a7e56db7" />
  <br><em>Pattern controls, custom sites, and config export</em>
</p>

<p align="center">
  <img width="720" alt="Local encrypted vault" src="https://github.com/user-attachments/assets/72d03545-0ed8-4737-8d99-bc6f109439ad" />
  <br><em>One-click unmask from the local encrypted vault</em>
</p>

---

## Install

**[Add from Chrome Web Store](https://chromewebstore.google.com/detail/secret-sanitizer/genolcmpopiemhpbdnhkaefllchgekja)** — one click, auto-updates.

<details>
<summary><strong>Manual / Developer install</strong></summary>

```bash
git clone https://github.com/souvikghosh957/secret-sanitizer-extension.git
cd secret-sanitizer-extension
```

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** and select the cloned folder

</details>

---

## Privacy & Security

| Claim | How to check |
|-------|-------------|
| No network requests | `grep -r "fetch\|XMLHttpRequest" content_script.js` → zero results |
| No tracking | No analytics, no telemetry, no third-party scripts |
| No remote code | All pattern matching is local regex |
| Works offline | Disable Wi-Fi and try it |
| Open source | MIT licensed — you're reading it right now |

---

## Roadmap

- [x] Smart Restore — auto-restore secrets when copying AI responses
- [ ] Firefox support
- [ ] Coding agent support — Cursor, Windsurf, Bolt.new, v0.dev, Lovable
- [ ] CLI tool support — Claude Code, OpenAI Codex CLI, Gemini CLI
- [ ] Pattern sharing — community-contributed pattern packs

---

## Contributing

Contributions are welcome.

- **New patterns** — know a secret format we're missing? Open a PR
- **False positives** — help fine-tune detection
- **Platform requests** — want a new AI chat or coding tool added?

Please open an issue first for larger changes.

---

## License

[MIT](LICENSE) — use it, fork it, improve it.

<p align="center">
  <br>If Secret Sanitizer has saved you from a leak, a star helps others find it.
</p>

<p align="center">
  <a href="https://github.com/souvikghosh957/secret-sanitizer-extension/stargazers">
    <img src="https://img.shields.io/github/stars/souvikghosh957/secret-sanitizer-extension?style=for-the-badge&color=yellow&logo=github" alt="Star this repo"/>
  </a>
</p>

<p align="center">
  <sub>Built by <a href="https://x.com/souvik_ghosh975">@souvik_ghosh975</a> &nbsp;&bull;&nbsp; <a href="mailto:souvikghosh2593@gmail.com">souvikghosh2593@gmail.com</a></sub>
</p>
