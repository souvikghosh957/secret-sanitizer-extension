# Contributing to Secret Sanitizer

Thanks for your interest in contributing! This guide will help you get started.

## Ways to Contribute

- **Report bugs** -- found a false positive or missed secret? Open an issue
- **Add new patterns** -- know a secret format we're missing? Submit a PR
- **Request platform support** -- want a new AI chat site added?
- **Improve docs** -- better examples, typo fixes, translations

## Getting Started

### Development Setup

```bash
git clone https://github.com/souvikghosh957/secret-sanitizer-extension.git
cd secret-sanitizer-extension
```

1. Open `chrome://extensions` in Chrome
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** and select the cloned folder
4. The extension icon should appear in your toolbar

### Project Structure

```
├── manifest.json          # Extension manifest (v3)
├── content_script.js      # Core logic — paste interception, pattern matching, encryption
├── background.js          # Service worker — vault cleanup, stats, milestones
├── popup/
│   ├── popup.html         # Extension popup markup
│   ├── popup.js           # Popup logic — settings, vault, stats
│   └── popup.css          # Popup styles
└── icons/                 # Extension icons (16, 48, 128)
```

### Making Changes

1. Fork the repo and create a branch from `master`
2. Make your changes
3. Test the extension locally on at least one AI platform (ChatGPT, Claude, etc.)
4. Verify no regressions — paste a known secret and confirm it gets masked
5. Open a PR with a clear description of what changed and why

## Adding a New Secret Pattern

Patterns live in `content_script.js` inside the `SECRET_PATTERNS` array. Each pattern has:

```js
{
  name: "Pattern Name",
  pattern: /your-regex-here/g,
  description: "What this pattern detects"
}
```

When adding a new pattern:

1. Add it to the `SECRET_PATTERNS` array
2. Use the `g` (global) flag
3. Test against real examples and edge cases
4. Make sure it doesn't cause excessive false positives
5. Add it to the README's "Supported Patterns" table if it's a new category

## Reporting Bugs

Open a [GitHub issue](https://github.com/souvikghosh957/secret-sanitizer-extension/issues) with:

- **What happened** -- describe the unexpected behavior
- **What you expected** -- describe the correct behavior
- **Steps to reproduce** -- which site, what text you pasted
- **Browser version** -- Chrome version number
- **Extension version** -- visible in the popup header

## Reporting False Positives

If a legitimate (non-secret) string is being masked:

1. Note which pattern triggered it (shown in the toast notification)
2. Open an issue with the text that was incorrectly flagged
3. Do NOT include actual secrets in issues -- use dummy/example values

## Code Style

- No build step -- the extension runs as plain JS/CSS/HTML
- Keep it simple and readable
- Comment non-obvious logic, but don't over-comment
- Avoid adding dependencies -- the extension is intentionally zero-dependency

## Pull Request Guidelines

- Keep PRs focused -- one feature or fix per PR
- Open an issue first for larger changes so we can discuss the approach
- Update the README if your change affects user-facing behavior
- Test on at least one supported platform before submitting

## Code of Conduct

Be respectful and constructive. We're all here to make developers' lives more secure.

## Questions?

Open an issue or reach out on [X (@souvik_ghosh975)](https://x.com/souvik_ghosh975).
