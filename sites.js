// Shared protected-site helpers — loaded by background.js (importScripts), popup.js and the
// content script. Keeping the default list and hostname validation in one place prevents drift
// between what the popup shows and what the service worker actually registers.

const DEFAULT_SITES = [
  "chatgpt.com", "claude.ai", "gemini.google.com", "grok.com"
];

// Offered as one-click opt-ins through optional_host_permissions. Adding any of these to
// DEFAULT_SITES / host_permissions would make Chrome disable the extension for every existing
// user until they re-approve it.
const SUGGESTED_SITES = [
  "www.perplexity.ai", "chat.deepseek.com", "copilot.com", "chat.mistral.ai", "www.meta.ai"
];

const PAUSE_DURATION_MS = 10 * 60 * 1000;

const SITE_HOSTNAME_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

// Normalizes user input ("https://Foo.com/path", "foo.com:8080") to a lowercase
// host[:port]. Returns null for anything that isn't a plain http(s) web host, so a
// malformed entry (e.g. from an imported settings file) can never reach
// chrome.scripting.registerContentScripts.
function normalizeSite(input) {
  if (typeof input !== "string") return null;
  const s = input.trim().toLowerCase();
  if (!s || s.length > 300) return null;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//.test(s) ? s : "https://" + s);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.username || url.password) return null;
    if (!SITE_HOSTNAME_RE.test(url.hostname)) return null;
    return url.host;
  } catch (_) {
    return null;
  }
}

// Hostname without port — used for match patterns (which match every port) and for
// comparing against a tab's location.hostname.
function siteHostname(site) {
  return site.replace(/:\d+$/, "");
}

function siteMatchPattern(site) {
  return `*://${siteHostname(site)}/*`;
}

// pause: { pausedUntil: epoch ms, pausedSites: [hostname] } as kept in chrome.storage.local.
// Anything malformed reads as "not paused", so bad state can only ever over-mask.
function isPaused(pause, hostname, now = Date.now()) {
  if (!pause) return false;
  if (typeof pause.pausedUntil === "number" && now < pause.pausedUntil) return true;
  return Array.isArray(pause.pausedSites) && pause.pausedSites.includes(hostname);
}

if (typeof module !== "undefined") {
  module.exports = {
    DEFAULT_SITES, SUGGESTED_SITES, PAUSE_DURATION_MS, normalizeSite, siteHostname, siteMatchPattern, isPaused
  };
}
