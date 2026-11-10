<p align="center">
  <img src="readme-heading.png" alt="Secret Sanitizer — Paste freely. Leak nothing. A pasted Stripe key shows up in the AI chat as [STRIPE_KEY_0]." />
</p>

<p align="center">
  A Chrome extension that masks API keys, tokens, and passwords <strong>in your browser</strong>, before they reach ChatGPT, Claude, Gemini, or Grok.<br>
  70+ patterns · works offline · no tracking · MIT licensed
</p>

<p align="center">
  <a href="#the-problem">The Problem</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#smart-restore">Smart Restore</a> &bull;
  <a href="#supported-platforms">Platforms</a> &bull;
  <a href="#what-it-catches">What It Catches</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#screenshots">Screenshots</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#privacy--security">Privacy</a> &bull;
  <a href="#contact">Contact</a>
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
  Paste your code &rarr; secrets become placeholders like <code>[STRIPE_KEY_k3f9_0]</code> &rarr; originals stay on your machine.
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
AI receives:  DATABASE_URL=[DB_CONN_k3f9_0]
Vault stores: postgres://admin:s3cret@db.prod.internal:5432/myapp  ← in memory only
```

1. You paste text into an AI chat.
2. The extension catches the paste before it reaches the input box.
3. Patterns run locally in your browser. Nothing leaves your machine.
4. Each secret is replaced with a readable placeholder like `[STRIPE_KEY_k3f9_0]`. The short id (`k3f9`) is new for every paste, so two different keys never share a name.
5. A toast shows what was caught, with a 5-second **Undo**.
6. The originals go into a memory-only vault. They are never written to disk and are deleted after 15 minutes or when the browser closes.

> **Verify it yourself:** `grep -n "fetch\|XMLHttpRequest" *.js popup/*.js` — zero results.

---

## Smart Restore

When the AI replies using your placeholders, you get the real values back automatically.

**Example:**

1. You ask: *"Fix this connection string: `[DB_CONN_k3f9_0]`"*
2. AI replies: *"Change `[DB_CONN_k3f9_0]` to use port 5433."*
3. You copy the reply. Your clipboard now holds the real connection string, ready to paste into your code.

No manual lookup and no digging through the vault. Originals are kept for 15 minutes. Until then, you can also paste a placeholder into the popup to see its original.

**The AI site never sees your originals:**

- Restored text goes straight to your clipboard from the extension's isolated context, never into the page.
- It only happens when you click a copy button or press a copy shortcut. Typing in the chat doesn't trigger it.
- It only works on the site where you pasted the secret.
- It turns itself off while masking is paused, and on sites you've allowed to read your clipboard.
- If you paste restored text back into the chat, it gets masked again.

---

## Supported Platforms

Works out of the box on:

| ChatGPT | Claude | Gemini | Grok |
|:-------:|:------:|:------:|:----:|
| ✓ | ✓ | ✓ | ✓ |

One click in the popup adds Perplexity, DeepSeek, Copilot, Mistral, or Meta AI. You can also add any other site by its domain.

---

## What It Catches

**Credentials & Tokens**
- Passwords, bearer tokens, Basic auth headers, JWTs
- OTP codes, PINs, OAuth & refresh tokens

**API Keys**
- AWS, Google Cloud, Azure
- OpenAI, Anthropic, Groq, HuggingFace
- Stripe, Square, Razorpay, Paytm
- GitHub, GitLab (personal access tokens)
- Slack, Twilio, SendGrid, Mailgun
- Discord, Slack and Teams webhooks, Telegram bot tokens

**Infrastructure**
- PostgreSQL, MySQL, MongoDB, Redis, RabbitMQ connection URLs
- Firebase, Vercel, DigitalOcean, Supabase, Heroku, Cloudflare
- Shopify, NPM, PyPI tokens
- `.env` key-value pairs

**Private & Sensitive Data**
- RSA, SSH, PGP private keys
- Aadhaar, PAN, GSTIN, UPI IDs
- Credit card numbers
- Random-looking tokens and base64-encoded secrets

> Stack traces, hashes, pod names, ARNs and other everyday debugging output stay readable. If something still gets masked by mistake, click **Not a secret?** on the toast, or turn that rule off in the popup.

---

## Features

| | |
|---|---|
| **Instant interception** | Secrets never reach the chat input |
| **Memory-only vault** | Originals never touch disk, expire after 15 minutes |
| **Smart Restore** | Copy AI responses and secrets auto-restore in your clipboard |
| **Undo on paste** | 5-second window to revert any masked paste |
| **Pause** | Pause for 10 minutes or on one site, with a clear `OFF` badge |
| **Not a secret?** | Allow one value (stored only as a salted hash) or turn off a guessing rule, right from the toast |
| **Test mode** | Preview what would be masked before committing |
| **Rule controls** | Turn individual rules on or off, in plain language with an example each |
| **More AI chats** | One-click opt-in for Perplexity, DeepSeek, Copilot, Mistral and Meta AI, or add any domain |
| **Stats dashboard** | See how many secrets were caught and when |
| **Backup & restore** | Export and import your config as JSON |
| **Dark mode** | Follows your system theme, or toggle it yourself |

---

## Screenshots

<p align="center">
  <img width="720" alt="Instant feedback when a secret is detected" src="https://github.com/user-attachments/assets/53c82a0b-75d0-467c-bd49-322ad0eab5d5" />
  <br><em>Instant feedback when a secret is detected and masked</em>
</p>

<p align="center">
  <img width="720" alt="Popup with controls" src="https://github.com/user-attachments/assets/3ce4f70e-d33a-4af4-904f-1e2888da6b35" />
  <br><em>The popup and its main controls</em>
</p>

<p align="center">
  <img width="720" alt="Pattern controls and custom sites" src="https://github.com/user-attachments/assets/270e6b89-0e73-4e6f-ae8a-bbe2a7e56db7" />
  <br><em>Pattern controls, custom sites, and config export</em>
</p>

<p align="center">
  <img width="720" alt="Memory-only vault" src="https://github.com/user-attachments/assets/72d03545-0ed8-4737-8d99-bc6f109439ad" />
  <br><em>One-click unmask from the memory-only vault</em>
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
2. Turn on **Developer mode**
3. Click **Load unpacked** and select the cloned folder

Requires Chrome 111 or later.

</details>

---

## Privacy & Security

| Claim | How to check |
|-------|-------------|
| No network requests | `grep -n "fetch\|XMLHttpRequest" *.js popup/*.js` → zero results |
| No tracking | No analytics, no telemetry, no third-party scripts |
| No remote code | All pattern matching is local regex |
| Works offline | Disable Wi-Fi and try it |
| Uninstall page | Chrome opens one static page when you uninstall. It has no scripts or analytics, and nothing about you is in its address |
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

Contributions are welcome — whether it's a bug report, a new pattern, or a feature idea.

**Ways to contribute:**

- **New secret patterns** — know a format we don't catch yet? Open a PR with the regex and a test case
- **False positives** — found something getting masked that shouldn't be? File an issue with an example
- **Platform support** — want Secret Sanitizer on a new AI chat or coding tool? Open a feature request

**Before submitting a PR**, please open an issue first so we can align on the approach. This avoids wasted effort on both sides.

[Open an issue →](https://github.com/souvikghosh957/secret-sanitizer-extension/issues/new)

---

## Contact

Have a question or idea? Found a security issue? Please report it privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.

- **GitHub Issues** — [github.com/souvikghosh957/secret-sanitizer-extension/issues](https://github.com/souvikghosh957/secret-sanitizer-extension/issues) — best for bugs and feature requests
- **X** — [@souvik_ghosh975](https://x.com/souvik_ghosh975)

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
  <sub>
    Built by <a href="https://x.com/souvik_ghosh975">@souvik_ghosh975</a>
  </sub>
</p>
