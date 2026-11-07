// Every string the code asks for must exist in the default locale, and any other locale must
// match it, including $1 placeholders.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { ROOT, loadScripts, loadDetector } = require("./helpers");

const read = (f) => fs.readFileSync(path.join(ROOT, f), "utf8");
const en = JSON.parse(read("_locales/en/messages.json"));
const otherLocales = fs.readdirSync(path.join(ROOT, "_locales")).filter(l => l !== "en")
  .map(l => JSON.parse(read(`_locales/${l}/messages.json`)));
const placeholders = (s) => [...new Set(s.match(/\$\d/g) || [])].sort().join();

test("locales have the same keys and placeholders", () => {
  for (const locale of otherLocales) {
    assert.deepEqual(Object.keys(locale).sort(), Object.keys(en).sort());
    for (const key of Object.keys(en)) {
      assert.equal(placeholders(locale[key].message), placeholders(en[key].message), key);
      assert.ok(locale[key].message.trim(), key);
    }
  }
});

test("keys use only characters Chrome accepts", () => {
  for (const key of Object.keys(en)) assert.match(key, /^[A-Za-z0-9_@]+$/);
});

test("every key used in code and markup exists", () => {
  const used = new Set();
  for (const f of ["content_script.js", "popup/popup.js", "background.js"]) {
    for (const m of read(f).matchAll(/\b(?:t|getMessage)\("([a-z0-9_]+)"/g)) used.add(m[1]);
    for (const m of read(f).matchAll(/\bt\([^)]*\?\s*"([a-z0-9_]+)"\s*:\s*"([a-z0-9_]+)"/g)) { used.add(m[1]); used.add(m[2]); }
  }
  for (const m of read("popup/popup.html").matchAll(/data-i18n(?:-placeholder|-title)?="([a-z0-9_]+)"/g)) used.add(m[1]);
  assert.ok(used.size > 80);
  for (const key of used) assert.ok(en[key], `missing message: ${key}`);
});

test("manifest strings are localized and fit Chrome's limits", () => {
  const manifest = JSON.parse(read("manifest.json"));
  assert.equal(manifest.default_locale, "en");
  for (const messages of [en, ...otherLocales]) {
    assert.ok(messages.ext_name.message.length <= 75);
    assert.ok(messages.ext_description.message.length <= 132);
  }
});

test("every detection rule has a plain-language name and an example", () => {
  const { SHARED_PATTERNS } = loadDetector();
  const { get } = loadScripts(["popup/pattern_examples.js"]);
  const examples = get("PATTERN_EXAMPLES");
  for (const label of new Set([...SHARED_PATTERNS.map(([, l]) => l), "ENTROPY"])) {
    assert.ok(en[`pattern_${label}`], `no name for ${label}`);
    assert.ok(examples[label], `no example for ${label}`);
  }
});

test("rule examples don't look like real secrets", () => {
  const { get } = loadScripts(["popup/pattern_examples.js"]);
  const d = loadDetector();
  const specific = /AWS_KEY|GITHUB|OPENAI|ANTHROPIC|STRIPE|SLACK_TOKEN|JWT|GOOGLE/;
  for (const example of Object.values(get("PATTERN_EXAMPLES"))) {
    assert.ok(!d.scan(example).labels.some(l => specific.test(l)), example);
  }
});

test("t falls back to the key when the extension context is gone", () => {
  const { get } = loadScripts(["i18n.js"], { chrome: { i18n: { getMessage() { throw new Error("Extension context invalidated"); } } } });
  assert.equal(get(`t("toast_undo")`), "toast_undo");
  assert.equal(get(`patternName("AWS_KEY")`), "AWS_KEY");
});
