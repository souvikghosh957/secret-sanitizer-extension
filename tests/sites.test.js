const test = require("node:test");
const assert = require("node:assert/strict");
const { normalizeSite, siteMatchPattern, DEFAULT_SITES } = require("../sites.js");

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
