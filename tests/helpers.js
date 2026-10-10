// Loads the extension's classic browser scripts into an isolated VM context, the same
// way Chrome shares top-level declarations between content-script files.
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..");

function loadScripts(files, globals = {}) {
  const context = vm.createContext({ console, crypto, URL, setTimeout, clearTimeout, ...globals });
  for (const file of files) {
    vm.runInContext(fs.readFileSync(path.join(ROOT, file), "utf8"), context, { filename: file });
  }
  return {
    context,
    get: (expr) => vm.runInContext(expr, context)
  };
}

function loadDetector() {
  const { get } = loadScripts(["patterns.js", "detector.js"]);
  const api = get(`({ SHARED_PATTERNS, DETECTOR_CONFIG, compilePatterns, findSecrets, maskText,
    newPasteId, makePlaceholder, findPlaceholders, placeholderLabel, PLACEHOLDER_TEST_RE,
    luhnValid, verhoeffValid })`);
  const compiled = api.compilePatterns(api.SHARED_PATTERNS);
  api.scan = (text, c = compiled) => {
    const { matches, partial } = api.findSecrets(text, c);
    const { maskedText, replacements } = api.maskText(text, matches, (label) => `[${label}]`);
    return { maskedText, replacements, partial, labels: matches.map(m => m.label) };
  };
  return api;
}

module.exports = { ROOT, loadScripts, loadDetector };
