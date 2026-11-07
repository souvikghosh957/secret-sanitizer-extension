const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { normalizeSite, siteMatchPattern, isPaused, DEFAULT_SITES, SUGGESTED_SITES } = require("../sites.js");

test("normalizeSite accepts plain hosts and URLs", () => {
  assert.equal(normalizeSite("example.com"), "example.com");
  assert.equal(normalizeSite("  HTTPS://Chat.Example.com/path?q=1 "), "chat.example.com");
  assert.equal(normalizeSite("localhost:3000"), "localhost:3000");
  assert.equal(normalizeSite("http://127.0.0.1:8080/"), "127.0.0.1:8080");
});

test("normalizeSite rejects anything that could break content script registration", () => {
  for (const bad of ["", "   ", "javascript:alert(1)", "chrome://extensions", "file:///etc/passwd",
    "ftp://x.com", "*.example.com", "exa mple.com", "user:pw@example.com", "-bad-.com", 42, null, {}]) {
    assert.equal(normalizeSite(bad), null, `accepted ${JSON.stringify(bad)}`);
  }
});

test("match patterns drop the port", () => {
  assert.equal(siteMatchPattern("localhost:3000"), "*://localhost/*");
  assert.equal(siteMatchPattern("example.com"), "*://example.com/*");
});

test("default sites are valid", () => {
  for (const site of DEFAULT_SITES) assert.equal(normalizeSite(site), site);
});

test("suggested sites are valid opt-ins, not defaults", () => {
  for (const site of SUGGESTED_SITES) {
    assert.equal(normalizeSite(site), site);
    assert.ok(!DEFAULT_SITES.includes(site));
  }
});

// A new required host permission makes Chrome disable the extension for every existing user
// until they re-approve it. New sites go through optional_host_permissions.
test("required host permissions stay limited to the default sites", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "manifest.json"), "utf8"));
  assert.deepEqual([...manifest.host_permissions].sort(), DEFAULT_SITES.map(siteMatchPattern).sort());
  assert.deepEqual(manifest.optional_host_permissions, ["*://*/*"]);
  assert.deepEqual([...manifest.permissions].sort(), ["activeTab", "alarms", "notifications", "scripting", "storage"]);
});

test("isPaused", () => {
  const now = 1000;
  assert.equal(isPaused({ pausedUntil: 1001 }, "claude.ai", now), true);
  assert.equal(isPaused({ pausedUntil: 1000 }, "claude.ai", now), false, "expires on time");
  assert.equal(isPaused({ pausedSites: ["claude.ai"] }, "claude.ai", now), true);
  assert.equal(isPaused({ pausedSites: ["claude.ai"] }, "chatgpt.com", now), false);
});

test("missing or malformed pause state never pauses", () => {
  for (const state of [null, undefined, {}, { pausedUntil: "9999999999999" }, { pausedSites: "claude.ai" }, { pausedUntil: null }]) {
    assert.equal(isPaused(state, "claude.ai", 1000), false, JSON.stringify(state));
  }
});
