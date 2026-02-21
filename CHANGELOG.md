# Changelog

All notable changes to Secret Sanitizer are documented here.

## [2.1.0] - 2025-12-XX

### Fixed
- Bug fixes for Chrome Web Store release

### Changed
- Improved stability and reliability

## [2.0.5] - 2025-12-XX

### Changed
- Redesigned popup with dark luxury premium theme
- Updated visual design for a premium security dashboard feel

## [2.0.4] - 2025-11-XX

### Fixed
- Fixed browsing history permission issue
- Fixed sites accordion toggling closed when navigating from status bar

### Changed
- Made welcome page feature points non-interactive

## [2.0.3] - 2025-11-XX

### Added
- Smart toast notifications with undo functionality
- Welcome screen for first-time users
- Site status indicator in popup
- Weekly summary and milestone celebrations (100, 500, 1K, 5K, 10K, 50K, 100K secrets protected)

### Removed
- Context menu integration (simplified UX)

## [2.0.2] - 2025-10-XX

### Fixed
- Improved short message check for Indian PII patterns

## [2.0.1] - 2025-10-XX

### Changed
- Redesigned popup UI with hero stats and unified action area

## [2.0.0] - 2025-10-XX

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

## [1.0.0] - 2025-09-XX

### Added
- Initial release
- Basic paste interception on AI chat platforms
- Regex-based secret detection (API keys, passwords, tokens, database URLs, private keys)
- Toast notification on secret detection
- Support for ChatGPT, Claude, Gemini, Grok, Perplexity, DeepSeek
