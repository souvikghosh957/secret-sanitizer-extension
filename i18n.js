// Translation helpers shared by the content script and the popup. Strings live in _locales/.

// getMessage throws in a content script whose extension was reloaded or updated, and a toast
// must never break a paste.
function t(key, substitutions) {
  try {
    return chrome.i18n.getMessage(key, substitutions) || key;
  } catch (_) {
    return key;
  }
}

// Plain-language name of a detection rule (for toasts and the popup, instead of internal labels).
function patternName(label) {
  const key = `pattern_${label}`;
  const name = t(key);
  return name === key ? label : name;
}

// Fills static markup: data-i18n (text), data-i18n-placeholder, data-i18n-title (title + aria-label).
function localizePage(root = document) {
  document.documentElement.lang = t("locale_code");
  root.querySelectorAll("[data-i18n]").forEach(el => { el.textContent = t(el.dataset.i18n); });
  root.querySelectorAll("[data-i18n-placeholder]").forEach(el => { el.placeholder = t(el.dataset.i18nPlaceholder); });
  root.querySelectorAll("[data-i18n-title]").forEach(el => {
    el.title = t(el.dataset.i18nTitle);
    el.setAttribute("aria-label", el.title);
  });
}
