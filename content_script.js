// Config
const CONFIG = {
  minTextLength: 6, // Skip processing very short text
  gestureWindowMs: 5000, // Smart Restore: max age of the trusted click/keypress behind a copy
  contextMenuWindowMs: 60000, // Smart Restore: right-click → "Copy" may take a while (ends at the next click or key)
  noticeThrottleMs: 30000, // At most one "scanned" or "paused" notice per paste burst
  cleanToastLimit: 3, // The "nothing to mask" toast is onboarding: it stops after this many
  reviewDelayMs: 6000 // Review prompt waits for the masked toast to go away
};

// Unique ID counter for SVG gradient IDs (prevents DOM collisions when multiple toasts coexist)
let _ssIconId = 0;

// Above this many distinct values the toast offers rule-level opt-out only (mirrors background.js).
const MAX_ALLOW_FROM_TOAST = 200;

// Check if extension context is still valid
function isExtensionContextValid() {
  try {
    // Check all required chrome APIs exist and context is valid
    if (!chrome || !chrome.runtime || !chrome.runtime.id) return false;
    if (!chrome.storage || !chrome.storage.local) return false;
    return true;
  } catch (_) {
    return false;
  }
}

// Safe wrapper for chrome.storage.local operations
function safeStorageGet(keys) {
  return new Promise((resolve) => {
    try {
      if (!isExtensionContextValid()) {
        resolve({});
        return;
      }
      chrome.storage.local.get(keys, (result) => {
        if (chrome.runtime.lastError) {
          resolve({});
        } else {
          resolve(result || {});
        }
      });
    } catch (_) {
      resolve({});
    }
  });
}

function safeStorageSet(data) {
  return new Promise((resolve) => {
    try {
      if (!isExtensionContextValid()) {
        resolve();
        return;
      }
      chrome.storage.local.set(data, () => {
        if (chrome.runtime.lastError) {
          console.warn('Storage write failed:', chrome.runtime.lastError.message);
        }
        resolve();
      });
    } catch (_) {
      resolve();
    }
  });
}

// Safe wrapper for messages to the background worker — resolves null on any failure
function sendToBackground(message) {
  return new Promise((resolve) => {
    try {
      if (!isExtensionContextValid()) {
        resolve(null);
        return;
      }
      chrome.runtime.sendMessage(message, (response) => {
        resolve(chrome.runtime.lastError ? null : (response ?? null));
      });
    } catch (_) {
      resolve(null);
    }
  });
}

// Patterns live in patterns.js and the engine in detector.js (both shared with popup.js).
// Until settings load: every pattern on, nothing allowed, not paused — so a paste that lands
// early is over-masked rather than leaked.
let COMPILED_PATTERNS = compilePatterns(SHARED_PATTERNS);
let _allowedValues = new Set();
let _allowSalt = null;
let _pause = null;
let _cleanToastCount = Infinity;

async function loadSettings() {
  try {
    const { disabledPatterns = [], allowedValues = [], allowSalt = null, pausedUntil, pausedSites, cleanToastCount = 0 } =
      await safeStorageGet(["disabledPatterns", "allowedValues", "allowSalt", "pausedUntil", "pausedSites", "cleanToastCount"]);
    COMPILED_PATTERNS = compilePatterns(SHARED_PATTERNS, disabledPatterns);
    _allowedValues = new Set(allowedValues);
    _allowSalt = allowSalt;
    _pause = { pausedUntil, pausedSites };
    _cleanToastCount = cleanToastCount;
  } catch (_) {
    // Keep the current settings
  }
}

// Chrome clears a tab's badge when it navigates, so a paused site asks for its badge back.
loadSettings().then(() => {
  if (Array.isArray(_pause?.pausedSites) && _pause.pausedSites.includes(location.hostname)) {
    sendToBackground({ action: "badge:sync" });
  }
});
if (isExtensionContextValid()) {
  // Apply popup and toast changes without requiring a page reload
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes.disabledPatterns || changes.allowedValues || changes.allowSalt ||
        changes.pausedUntil || changes.pausedSites) {
      loadSettings();
    }
    // Shared across tabs, so the onboarding toast stops after three pastes in total
    if (changes.cleanToastCount) _cleanToastCount = changes.cleanToastCount.newValue ?? 0;
  });
}

// Detect + mask. Returns { maskedText, replacements, partial }. Nothing is cached here: originals
// are kept only in the vault, which expires. Every paste gets a random id baked into its
// placeholders ([OPENAI_KEY_k3f9_0]) so placeholders from different pastes never collide.
function sanitizeText(text) {
  const { matches: found, partial } = findSecrets(text, COMPILED_PATTERNS);
  const matches = dropAllowedValues(found, _allowedValues, _allowSalt);
  const pasteId = newPasteId();
  const { maskedText, replacements } = maskText(text, matches, (label, i) => makePlaceholder(label, pasteId, i));
  return { maskedText, replacements, partial };
}

// The vault lives in the background worker's memory-only storage (chrome.storage.session):
// never written to disk and never readable by the page. Stats are updated there too.
async function saveToVault(replacements) {
  const res = await sendToBackground({ action: "vault:save", replacements });
  if (!res?.ok) throw new Error(res?.error || "vault unavailable");
}

// All toasts live in one column fixed to the bottom-right corner, high enough to clear a
// composer's send button, so they can never overlap each other. It ignores the pointer except
// on the toasts themselves.
function mountToast(toast) {
  let stack = document.getElementById("ss-toast-stack");
  if (!stack) {
    stack = document.createElement("div");
    stack.id = "ss-toast-stack";
    Object.assign(stack.style, {
      position: "fixed",
      bottom: "80px",
      right: "16px",
      display: "flex",
      flexDirection: "column-reverse",
      alignItems: "flex-end",
      gap: "8px",
      zIndex: "2147483647",
      pointerEvents: "none"
    });
    document.body.appendChild(stack);
  }
  if (toast.style.pointerEvents !== "none") toast.style.pointerEvents = "auto";
  stack.appendChild(toast);
}

// Toast buttons must never take focus from the editor, or typing stops mid-word.
function keepEditorFocus(el) {
  el.addEventListener("mousedown", (e) => e.preventDefault());
}

// Simple toast for basic messages — styled to match the smart toast's dark card
function showToast(message, type = "success") {
  if (!document.body) return;
  document.querySelectorAll(".secret-sanitizer-toast").forEach(t => t.remove());

  const toast = document.createElement("div");
  toast.className = "secret-sanitizer-toast";
  toast.setAttribute("role", "alert");

  const colors = {
    success: { accent: "#10b981", icon: "✓" },
    warning: { accent: "#f59e0b", icon: "!" },
    error: { accent: "#ef4444", icon: "✕" },
    info: { accent: "#0ea5e9", icon: "✓" }
  };
  const style = colors[type] || colors.success;

  Object.assign(toast.style, {
    background: "#1e293b",
    color: "#f1f5f9",
    padding: "0",
    borderRadius: "12px",
    boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
    fontFamily: "system-ui, -apple-system, sans-serif",
    fontSize: "13px",
    fontWeight: "500",
    opacity: "0",
    transform: "translateY(16px)",
    transition: "all 0.25s ease-out",
    overflow: "hidden"
  });

  const content = document.createElement("div");
  Object.assign(content.style, {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    padding: "12px 16px"
  });

  const iconDot = document.createElement("div");
  Object.assign(iconDot.style, {
    width: "24px",
    height: "24px",
    borderRadius: "7px",
    background: style.accent,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "12px",
    fontWeight: "700",
    color: "#fff",
    flexShrink: "0",
    lineHeight: "1"
  });
  iconDot.textContent = style.icon;

  const msgSpan = document.createElement("span");
  msgSpan.textContent = message;
  content.appendChild(iconDot);
  content.appendChild(msgSpan);
  toast.appendChild(content);
  mountToast(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";
  });

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(16px)";
    setTimeout(() => toast.remove(), 250);
  }, 3000);
}

// Subtle "clean" toast - tells a new user the extension is on. Stops after the first few.
function showCleanToast() {
  if (!document.body || _cleanToastCount >= CONFIG.cleanToastLimit) return;
  if (showCleanToast._lastShown && Date.now() - showCleanToast._lastShown < CONFIG.noticeThrottleMs) return;
  showCleanToast._lastShown = Date.now();
  _cleanToastCount++;
  safeStorageSet({ cleanToastCount: _cleanToastCount });

  document.querySelectorAll(".secret-sanitizer-clean-toast").forEach(t => t.remove());

  const toast = document.createElement("div");
  toast.className = "secret-sanitizer-clean-toast";
  toast.setAttribute("role", "status");

  Object.assign(toast.style, {
    background: "#1e293b",
    color: "#94a3b8",
    padding: "0",
    borderRadius: "12px",
    boxShadow: "0 4px 16px rgba(0,0,0,0.2)",
    fontFamily: "system-ui, -apple-system, sans-serif",
    fontSize: "12px",
    fontWeight: "500",
    opacity: "0",
    transform: "translateY(12px)",
    transition: "all 0.25s ease-out",
    pointerEvents: "none",
    overflow: "hidden"
  });

  const content = document.createElement("div");
  Object.assign(content.style, {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    padding: "10px 14px"
  });

  const iconWrap = document.createElement("div");
  Object.assign(iconWrap.style, {
    width: "22px",
    height: "22px",
    borderRadius: "6px",
    background: "rgba(52,211,153,0.12)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: "0"
  });
  const _svgClean = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  _svgClean.setAttribute("width", "14");
  _svgClean.setAttribute("height", "14");
  _svgClean.setAttribute("viewBox", "0 0 24 24");
  _svgClean.setAttribute("fill", "none");
  const _cpShield = document.createElementNS("http://www.w3.org/2000/svg", "path");
  _cpShield.setAttribute("d", "M12 2L4 5.5V11c0 5.25 3.4 10.2 8 11.5 4.6-1.3 8-6.25 8-11.5V5.5L12 2z");
  _cpShield.setAttribute("fill", "none");
  _cpShield.setAttribute("stroke", "#34d399");
  _cpShield.setAttribute("stroke-width", "1.5");
  const _cpCheck = document.createElementNS("http://www.w3.org/2000/svg", "path");
  _cpCheck.setAttribute("d", "M9 12.5l2 2 4-4.5");
  _cpCheck.setAttribute("stroke", "#34d399");
  _cpCheck.setAttribute("stroke-width", "2");
  _cpCheck.setAttribute("stroke-linecap", "round");
  _cpCheck.setAttribute("stroke-linejoin", "round");
  _cpCheck.setAttribute("fill", "none");
  _svgClean.appendChild(_cpShield);
  _svgClean.appendChild(_cpCheck);
  iconWrap.appendChild(_svgClean);

  const cleanMsg = document.createElement("span");
  cleanMsg.textContent = t("toast_active");
  content.appendChild(iconWrap);
  content.appendChild(cleanMsg);
  toast.appendChild(content);
  mountToast(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";
  });

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(12px)";
    setTimeout(() => toast.remove(), 250);
  }, 1500);
}

// Paused pastes go through untouched, so say so — but only once per burst of pastes.
function showPausedNotice() {
  if (showPausedNotice._lastShown && Date.now() - showPausedNotice._lastShown < CONFIG.noticeThrottleMs) return;
  showPausedNotice._lastShown = Date.now();
  showToast(t("toast_paused"), "warning");
}

function toastActionButton(text, onClick) {
  const btn = document.createElement("button");
  Object.assign(btn.style, {
    background: "rgba(255,255,255,0.08)",
    border: "none",
    color: "#94a3b8",
    padding: "4px 9px",
    borderRadius: "5px",
    fontSize: "11px",
    fontWeight: "500",
    cursor: "pointer",
    transition: "all 0.15s ease",
    flexShrink: "0"
  });
  btn.textContent = text;
  keepEditorFocus(btn);
  btn.onmouseenter = () => {
    btn.style.background = "rgba(255,255,255,0.15)";
    btn.style.color = "#f1f5f9";
  };
  btn.onmouseleave = () => {
    btn.style.background = "rgba(255,255,255,0.08)";
    btn.style.color = "#94a3b8";
  };
  btn.onclick = (e) => {
    // These put plaintext back into the page or relax masking. The toast lives in the page
    // DOM, so only honour real user clicks — page script can't forge isTrusted.
    if (!e.isTrusted) return;
    e.stopPropagation();
    onClick();
  };
  return btn;
}

// Masked-paste toast. replacements: [placeholder, original] pairs from this paste.
// onUndo restores everything and returns success; onRestore(subset) restores just those;
// onNotSecret(request) records the user's "don't mask this again" choice.
function showSmartToast(replacements, { onUndo, onRestore, onNotSecret, partial = false }) {
  if (!document.body) return;
  document.querySelectorAll(".secret-sanitizer-toast").forEach(t => t.remove());

  const toast = document.createElement("div");
  toast.className = "secret-sanitizer-toast";
  toast.setAttribute("role", "alert");

  const labels = replacements.map(([placeholder]) => placeholderLabel(placeholder) || "SECRET");
  const types = [...new Set(labels)].map(patternName);
  const typeDisplay = types.slice(0, 2).join(", ") + (types.length > 2 ? ` +${types.length - 2}` : "");

  Object.assign(toast.style, {
    background: "linear-gradient(135deg, #1e293b 0%, #182030 100%)",
    color: "#f1f5f9",
    padding: "0",
    borderRadius: "12px",
    border: "1px solid rgba(255,255,255,0.07)",
    boxShadow: "0 8px 24px rgba(0,0,0,0.35), 0 0 0 1px rgba(14,165,233,0.08)",
    fontFamily: "system-ui, -apple-system, sans-serif",
    fontSize: "12px",
    opacity: "0",
    transform: "translateY(8px)",
    transition: "all 0.2s ease-out",
    overflow: "hidden",
    maxWidth: "360px"
  });

  // Main content
  const content = document.createElement("div");
  Object.assign(content.style, {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    padding: "8px 8px 8px 11px"
  });

  // Shield icon
  const icon = document.createElement("div");
  const _sid1 = _ssIconId++;
  Object.assign(icon.style, {
    width: "22px",
    height: "22px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: "0"
  });
  const _svgSmart = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  _svgSmart.setAttribute("width", "20");
  _svgSmart.setAttribute("height", "20");
  _svgSmart.setAttribute("viewBox", "0 0 24 24");
  _svgSmart.setAttribute("fill", "none");
  const _defs1 = document.createElementNS("http://www.w3.org/2000/svg", "defs");
  const _grad1 = document.createElementNS("http://www.w3.org/2000/svg", "linearGradient");
  _grad1.setAttribute("id", `ss-sg${_sid1}`);
  _grad1.setAttribute("x1", "0"); _grad1.setAttribute("y1", "0");
  _grad1.setAttribute("x2", "1"); _grad1.setAttribute("y2", "1");
  const _stop1a = document.createElementNS("http://www.w3.org/2000/svg", "stop");
  _stop1a.setAttribute("offset", "0%"); _stop1a.setAttribute("stop-color", "#0ea5e9");
  const _stop1b = document.createElementNS("http://www.w3.org/2000/svg", "stop");
  _stop1b.setAttribute("offset", "100%"); _stop1b.setAttribute("stop-color", "#06b6d4");
  _grad1.appendChild(_stop1a); _grad1.appendChild(_stop1b);
  _defs1.appendChild(_grad1); _svgSmart.appendChild(_defs1);
  const _sp1 = document.createElementNS("http://www.w3.org/2000/svg", "path");
  _sp1.setAttribute("d", "M12 2L4 5.5V11c0 5.25 3.4 10.2 8 11.5 4.6-1.3 8-6.25 8-11.5V5.5L12 2z");
  _sp1.setAttribute("fill", `url(#ss-sg${_sid1})`);
  _sp1.setAttribute("stroke", "#94a3b8"); _sp1.setAttribute("stroke-width", "0.8");
  const _sp2 = document.createElementNS("http://www.w3.org/2000/svg", "path");
  _sp2.setAttribute("d", "M9 12.5l2 2 4-4.5");
  _sp2.setAttribute("stroke", "#fff"); _sp2.setAttribute("stroke-width", "2");
  _sp2.setAttribute("stroke-linecap", "round"); _sp2.setAttribute("stroke-linejoin", "round");
  _sp2.setAttribute("fill", "none");
  _svgSmart.appendChild(_sp1); _svgSmart.appendChild(_sp2);
  icon.appendChild(_svgSmart);

  // Single-line label: "5 secrets masked"
  const label = document.createElement("div");
  Object.assign(label.style, {
    flex: "1",
    minWidth: "0",
    fontWeight: "600",
    fontSize: "12px",
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis"
  });
  label.textContent = t(replacements.length === 1 ? "toast_masked_one" : "toast_masked_many", [String(replacements.length)]) +
    (partial ? " \u00b7 " + t("toast_partial") : "");
  label.title = partial ? `${typeDisplay} \u2014 ${t("toast_partial_detail")}` : typeDisplay; // full type list on hover

  content.appendChild(icon);
  content.appendChild(label);

  // Auto-dismiss after 5 seconds (longer to allow undo)
  // Declared before undo button so the onclick closure can reference it
  let dismissTimeout;

  const dismiss = () => {
    clearTimeout(dismissTimeout);
    toast.style.opacity = "0";
    toast.style.transform = "translateY(8px)";
    setTimeout(() => toast.remove(), 200);
  };

  const finish = (message, ok = true) => {
    clearTimeout(dismissTimeout);
    toast.remove();
    showToast(message, ok ? "success" : "error");
  };

  content.appendChild(toastActionButton(t("toast_undo"), () => {
    const restored = onUndo();
    finish(t(restored ? "toast_undo_done" : "toast_undo_failed"), restored);
  }));

  // Only generic rules can be waved through: a recognised key format stays masked unless Undone.
  const generic = replacements.filter(([placeholder]) => GENERIC_LABELS.has(placeholderLabel(placeholder)));
  let panel = null;
  if (generic.length > 0) {
    panel = document.createElement("div");
    Object.assign(panel.style, { display: "none", flexDirection: "column", gap: "4px", padding: "0 8px 8px" });
    panel.addEventListener("click", (e) => e.stopPropagation());

    const allow = async (items, request) => {
      const restored = onRestore(items);
      const saved = await onNotSecret(request);
      const ok = restored > 0 && saved?.ok === true;
      finish(t(ok ? "toast_allowed" : "toast_allow_failed"), ok);
    };

    const originals = [...new Set(generic.map(([, original]) => original))];
    if (originals.length <= MAX_ALLOW_FROM_TOAST) {
      panel.appendChild(toastActionButton(
        t(originals.length === 1 ? "toast_allow_one" : "toast_allow_many", [String(originals.length)]),
        () => allow(generic, { action: "allow:add", values: originals })
      ));
    }
    for (const ruleLabel of new Set(generic.map(([placeholder]) => placeholderLabel(placeholder)))) {
      panel.appendChild(toastActionButton(
        t("toast_stop_rule", [patternName(ruleLabel)]),
        () => allow(generic.filter(([placeholder]) => placeholderLabel(placeholder) === ruleLabel),
          { action: "rule:disable", label: ruleLabel })
      ));
    }
    panel.querySelectorAll("button").forEach(b => { b.style.textAlign = "left"; });

    const notSecretBtn = toastActionButton(t("toast_not_secret"), () => {
      // Stays open until the user chooses or closes it
      clearTimeout(dismissTimeout);
      panel.style.display = "flex";
      notSecretBtn.remove();
    });
    content.appendChild(notSecretBtn);
  }

  // Close (×) button — always shown so users can dismiss without waiting
  const closeBtn = document.createElement("button");
  Object.assign(closeBtn.style, {
    background: "none",
    border: "none",
    color: "#64748b",
    padding: "2px 4px",
    borderRadius: "4px",
    fontSize: "16px",
    lineHeight: "1",
    cursor: "pointer",
    flexShrink: "0",
    transition: "color 0.15s ease"
  });
  closeBtn.textContent = "×";
  closeBtn.setAttribute("aria-label", t("toast_dismiss"));
  keepEditorFocus(closeBtn);
  closeBtn.onmouseenter = () => { closeBtn.style.color = "#cbd5e1"; };
  closeBtn.onmouseleave = () => { closeBtn.style.color = "#64748b"; };
  closeBtn.onclick = (e) => {
    e.stopPropagation();
    dismiss();
  };
  content.appendChild(closeBtn);

  toast.appendChild(content);
  if (panel) toast.appendChild(panel);
  mountToast(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";
  });

  dismissTimeout = setTimeout(dismiss, 5000);

  // Clicking the toast body dismisses it too
  toast.addEventListener("click", dismiss);
}

// Replaces this paste's placeholders with their originals, inside the editor it was pasted
// into. Rich editors (Lexical, ProseMirror) split and reformat inserted text, so each placeholder
// is located on its own. Returns how many were restored.
function restorePlaceholders(target, replacements) {
  let restored = 0;
  if (target.isContentEditable) {
    target.focus();
    // Last first: replacing a placeholder can split the text node holding the earlier ones
    for (let i = replacements.length - 1; i >= 0; i--) {
      const [placeholder, original] = replacements[i];
      const walker = document.createTreeWalker(target, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        const idx = node.textContent.indexOf(placeholder);
        if (idx === -1) continue;
        const range = document.createRange();
        range.setStart(node, idx);
        range.setEnd(node, idx + placeholder.length);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        document.execCommand('insertText', false, original);
        restored++;
        break;
      }
    }
  } else if (target.value !== undefined) {
    target.focus();
    let value = target.value;
    for (const [placeholder, original] of replacements) {
      const idx = value.indexOf(placeholder);
      if (idx === -1) continue;
      value = value.substring(0, idx) + original + value.substring(idx + placeholder.length);
      restored++;
    }
    if (restored > 0) setFieldValue(target, value);
  }
  return restored;
}

// Uses the native setter so React and friends notice the change.
function setFieldValue(target, value) {
  const nativeSetter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(target), 'value')?.set;
  if (nativeSetter) {
    nativeSetter.call(target, value);
  } else {
    target.value = value;
  }
  target.dispatchEvent(new Event('input', { bubbles: true }));
  target.dispatchEvent(new Event('change', { bubbles: true }));
}

// The focused element, followed into shadow roots: a web-component editor is otherwise hidden
// behind its host, and a paste with secrets into it could never be completed.
function deepActiveElement() {
  let el = document.activeElement;
  while (el?.shadowRoot?.activeElement) el = el.shadowRoot.activeElement;
  return el;
}

// Paste handler — registered at document_start in the window capture phase, so it runs
// before any listener the page can add and the page never sees the unmasked paste.
window.addEventListener("paste", (e) => {
  // Synthetic paste events are built by page script from data the page already has
  if (!e.isTrusted) return;

  const clipboardText = e.clipboardData?.getData("text");
  if (!clipboardText || clipboardText.length < CONFIG.minTextLength) return;

  if (isPaused(_pause, location.hostname)) {
    showPausedNotice();
    return;
  }

  const { maskedText, replacements, partial } = sanitizeText(clipboardText);
  if (replacements.length === 0) {
    if (partial) {
      showToast(t("toast_large_paste"), "warning");
    } else if (clipboardText.length >= 200 || /\S{20,}/.test(clipboardText)) {
      showCleanToast();
    }
    return;
  }

  e.preventDefault();
  e.stopImmediatePropagation();

  const target = deepActiveElement();

  // Async save (don't block UI). Undo works without it; Smart Restore needs it.
  saveToVault(replacements).catch(() => {
    showToast(t("toast_vault_failed"), "warning");
  });

  let inserted = false;

  if (target && target.isContentEditable) {
    // ContentEditable (ChatGPT/Lexical, Claude/ProseMirror, Gemini):
    // execCommand('insertText') integrates with the editor's undo stack.
    try {
      inserted = document.execCommand('insertText', false, maskedText);
    } catch (_) {
      // execCommand is deprecated and may throw in sandboxed iframes — fallback below handles it
    }

    // Fallback: Selection API (no undo stack integration). Only when the selection really is
    // inside the editor — a range rescoped to a shadow host would land the text outside it.
    if (!inserted) {
      try {
        const sel = window.getSelection();
        if (sel.rangeCount > 0 && target.contains(sel.getRangeAt(0).commonAncestorContainer)) {
          const range = sel.getRangeAt(0);
          range.deleteContents();
          range.insertNode(document.createTextNode(maskedText));
          range.collapse(false);
          target.dispatchEvent(new Event('input', { bubbles: true }));
          inserted = true;
        }
      } catch (_) {
        // Selection API unavailable in this context — insertion will be skipped
      }
    }
  } else if (target && (target.tagName === 'TEXTAREA' || target.tagName === 'INPUT')) {
    // Textarea / Input elements
    try {
      const start = target.selectionStart || 0;
      const end = target.selectionEnd || 0;
      const value = target.value || '';
      const cursorPos = start + maskedText.length;
      setFieldValue(target, value.substring(0, start) + maskedText + value.substring(end));
      target.setSelectionRange(cursorPos, cursorPos);
      inserted = true;
    } catch (err) {
      console.warn("[SecretSanitizer] Failed to insert masked text into textarea:", err);
    }
  }

  if (inserted) {
    // No review prompt right after the user had to correct us.
    const reviewTimer = setTimeout(checkReviewPrompt, CONFIG.reviewDelayMs);

    showSmartToast(replacements, {
      partial,
      onUndo: () => {
        clearTimeout(reviewTimer);
        try {
          if (restorePlaceholders(target, replacements) > 0) return true;
          // Editor reformatted the placeholders beyond recognition: fall back to its undo stack
          if (target.isContentEditable) document.execCommand('undo');
          return false;
        } catch (_) {
          return false;
        }
      },
      onRestore: (items) => {
        clearTimeout(reviewTimer);
        try {
          return restorePlaceholders(target, items);
        } catch (_) {
          return 0;
        }
      },
      onNotSecret: (request) => sendToBackground(request)
    });
  } else {
    showToast(t("toast_insert_failed"), "error");
  }
}, true);

// ==================== SMART RESTORE (copy) ====================
//
// Security model: the page (and any script running in it) must never obtain original
// secrets. Restored text is therefore only ever written to the system clipboard from this
// isolated world via navigator.clipboard.writeText() — never through DOM events, the DOM,
// or e.clipboardData.setData() (the page's own copy listeners could getData() it).
// A restore also requires a recent *trusted* user gesture, which page script cannot forge,
// and is refused on sites the user has allowed to read the clipboard. It is refused while
// masking is paused too: a restored secret on the clipboard would reach the page on the next
// paste, since nothing masks it then.

let _lastGestureAt = 0;
let _lastContextMenuAt = 0;

// Only gestures that can mean "copy" count. Typing or clicking in a text field doesn't: those
// happen all the time, and page script could use them to trigger a restore (its own copy
// button call or execCommand('copy')) the user never asked for.
function isTextField(el) {
  if (!el) return false;
  if (el.isContentEditable || el.tagName === "TEXTAREA") return true;
  return el.tagName === "INPUT" && !/^(?:button|submit|reset|image|checkbox|radio)$/i.test(el.type);
}

// Ctrl/Cmd+C or Ctrl+Insert, and Ctrl/Cmd+Shift app shortcuts (ChatGPT's "copy last response").
// e.code covers non-Latin layouts, where Ctrl+C reports e.key "с".
function isCopyShortcut(e) {
  if (!e.ctrlKey && !e.metaKey) return false;
  const key = (e.key || "").toLowerCase();
  if (key === "c" || e.code === "KeyC" || key === "insert") return true;
  return e.shiftKey && key !== "v" && e.code !== "KeyV"; // Ctrl+Shift+V is a paste
}

// The element the event started on: e.target is retargeted to the host for editors in shadow DOM
const eventOrigin = (e) => e.composedPath?.()[0] || e.target;

// Choosing "Copy" from the context menu fires no pointer or key event on the page, so any such
// event means the menu is gone and its window can close early: page script shouldn't get a whole
// minute in which an execCommand('copy') of its own counts as the user's right-click → Copy.
// (For a right-click the pointerdown fires before contextmenu, so the window is set after this.)
window.addEventListener("pointerdown", (e) => {
  if (!e.isTrusted) return;
  _lastContextMenuAt = 0;
  if (!isTextField(eventOrigin(e))) _lastGestureAt = Date.now();
}, true);
window.addEventListener("keydown", (e) => {
  if (!e.isTrusted) return;
  _lastContextMenuAt = 0;
  // Enter/Space activate a focused copy button
  const activatesButton = (e.key === "Enter" || e.key === " ") && !isTextField(eventOrigin(e));
  if (activatesButton || isCopyShortcut(e)) _lastGestureAt = Date.now();
}, true);
window.addEventListener("contextmenu", (e) => { if (e.isTrusted) _lastContextMenuAt = Date.now(); }, true);

function hasRecentUserGesture() {
  return Date.now() - _lastGestureAt < CONFIG.gestureWindowMs;
}

// A site with clipboard-read permission could read restored secrets straight back.
let _siteCanReadClipboard = false;
try {
  navigator.permissions?.query({ name: "clipboard-read" }).then((status) => {
    const update = () => { _siteCanReadClipboard = status.state === "granted"; };
    update();
    status.addEventListener("change", update);
  }).catch(() => {});
} catch (_) {
  // Permissions API unavailable — nothing to check
}

function canSmartRestore() {
  if (!isExtensionContextValid()) return false;
  if (isPaused(_pause, location.hostname)) {
    showToast(t("toast_restore_paused"), "warning");
    return false;
  }
  if (_siteCanReadClipboard) {
    showToast(t("toast_restore_blocked"), "warning");
    return false;
  }
  return true;
}

function showRestoreToast(restoredCount, expiredCount) {
  if (expiredCount > 0) {
    showToast(t("toast_restored_expired", [String(restoredCount), String(expiredCount)]), 'warning');
  } else {
    showToast(t(restoredCount === 1 ? "toast_restored_one" : "toast_restored_many", [String(restoredCount)]), 'info');
  }
}

let _restoreSeq = 0;

// Resolves placeholders through the background vault (scoped to this site's origin) and
// writes the result to the clipboard. fallbackText is written when nothing resolves — used
// when we've taken over a page's own clipboard write and must still complete it.
async function restoreToClipboard(text, fallbackText) {
  const seq = ++_restoreSeq;
  const tokens = [...new Set(findPlaceholders(text))];
  const res = await sendToBackground({ action: "vault:resolve", tokens });
  if (seq !== _restoreSeq) return; // a newer copy superseded this one

  const values = (res && res.values) || {};
  const resolved = tokens.filter(t => typeof values[t] === "string");
  try {
    if (resolved.length > 0) {
      const restored = replacePlaceholders(text, (placeholder) => values[placeholder]);
      await navigator.clipboard.writeText(restored);
      showRestoreToast(resolved.length, tokens.length - resolved.length);
    } else if (fallbackText !== undefined) {
      await navigator.clipboard.writeText(fallbackText);
    }
  } catch (_) {
    showToast(t("toast_restore_failed"), "error");
  }
}

// Manual copy (Ctrl/Cmd+C, right-click → Copy) and page copy buttons that use
// execCommand('copy'). The browser/page completes the normal (masked) copy first; the
// async write below then replaces it with the restored text.
// On window, capture phase: this script runs before any page script, so its listener is first in
// line and sees every copy, including ones the page stops right there (ChatGPT's copy button
// does, so a document-level listener never saw them).
let _trustedCopyAt = 0;

window.addEventListener("copy", (e) => {
  if (!e.isTrusted) return; // synthetic copy events carry no real clipboard action
  _trustedCopyAt = Date.now();

  // Textarea elements keep their own selection, separate from window.getSelection()
  const t = e.target;
  const selected = (t && t.tagName === "TEXTAREA")
    ? t.value.substring(t.selectionStart || 0, t.selectionEnd ?? t.value.length)
    : (window.getSelection()?.toString() || "");
  if (!selected || !LOOSE_PLACEHOLDER_TEST_RE.test(selected)) return;

  const viaContextMenu = Date.now() - _lastContextMenuAt < CONFIG.contextMenuWindowMs;
  if (!hasRecentUserGesture() && !viaContextMenu) return;
  if (!canSmartRestore()) return;
  _lastContextMenuAt = 0;

  restoreToClipboard(selected);
}, true);

// Programmatic copy buttons (navigator.clipboard.writeText/write), relayed by
// ss_clipboard_interceptor.js. The event only ever carries masked text, and page script
// can dispatch it at will — hence the trusted-gesture requirement.
document.addEventListener("__ss_restore_request", (e) => {
  const text = e.detail;
  if (typeof text !== "string" || !LOOSE_PLACEHOLDER_TEST_RE.test(text)) return;
  if (!hasRecentUserGesture() || !canSmartRestore()) return;

  e.preventDefault(); // tells the MAIN-world wrapper we own this clipboard write
  restoreToClipboard(text, text);
});

// Copy buttons that put their text on the copy event (a copy listener calling
// e.clipboardData.setData(), usually with nothing selected), relayed by the interceptor. A page
// can call setData whenever it likes, so this only counts during a trusted copy event, and needs
// the same copy gesture as every other restore. The page's own copy completes first; the
// restored text replaces it afterwards.
document.addEventListener("__ss_restore_hint", (e) => {
  const text = e.detail;
  if (typeof text !== "string" || !LOOSE_PLACEHOLDER_TEST_RE.test(text)) return;
  if (Date.now() - _trustedCopyAt > 1000) return;
  const viaContextMenu = Date.now() - _lastContextMenuAt < CONFIG.contextMenuWindowMs;
  if (!hasRecentUserGesture() && !viaContextMenu) return;
  if (!canSmartRestore()) return;
  restoreToClipboard(text);
});

// ==================== REVIEW PROMPT ====================

const REVIEW_MILESTONES = [25, 50, 100, 500, 1000, 5000, 10000];

async function checkReviewPrompt() {
  try {
    const { stats = {}, reviewLastShownAt = 0, reviewDone = false } =
      await safeStorageGet(["stats", "reviewLastShownAt", "reviewDone"]);
    if (reviewDone) return;
    // One thing at a time: another toast is up, so try again after the next masked paste
    if (document.querySelector(".secret-sanitizer-toast, #ss-milestone-toast")) return;
    const total = stats.totalBlocked || 0;

    // Find the highest milestone the user has crossed
    let currentMilestone = 0;
    for (const m of REVIEW_MILESTONES) {
      if (total >= m) currentMilestone = m;
    }

    // Don't show if below first milestone or already shown at this milestone
    if (currentMilestone === 0) return;
    if (reviewLastShownAt >= currentMilestone) return;

    // Mark this milestone as shown before displaying
    await safeStorageSet({ reviewLastShownAt: currentMilestone });
    showReviewToast(currentMilestone, total);
  } catch (err) {
    console.warn("[SecretSanitizer] Review prompt error:", err);
  }
}

function showReviewToast(milestone, total) {
  if (!document.body) return;
  document.querySelectorAll(".secret-sanitizer-review-toast").forEach(t => t.remove());

  // Inject keyframes once
  if (!document.getElementById("ss-review-keyframes")) {
    const style = document.createElement("style");
    style.id = "ss-review-keyframes";
    style.textContent = `
      @keyframes ss-review-shimmer {
        0% { background-position: -200% 0; }
        100% { background-position: 200% 0; }
      }
      @keyframes ss-review-glow {
        0%, 100% { box-shadow: 0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(251,191,36,0.1), 0 0 20px rgba(251,191,36,0.05); }
        50% { box-shadow: 0 8px 40px rgba(0,0,0,0.5), 0 0 0 1px rgba(251,191,36,0.2), 0 0 30px rgba(251,191,36,0.1); }
      }
      @keyframes ss-star-spin {
        0% { transform: rotate(0deg) scale(1); }
        25% { transform: rotate(10deg) scale(1.1); }
        50% { transform: rotate(0deg) scale(1); }
        75% { transform: rotate(-10deg) scale(1.05); }
        100% { transform: rotate(0deg) scale(1); }
      }
`;
    document.head.appendChild(style);
  }

  const toast = document.createElement("div");
  toast.className = "secret-sanitizer-review-toast";
  toast.setAttribute("role", "alert");

  Object.assign(toast.style, {
    background: "linear-gradient(145deg, #0f172a 0%, #1e293b 50%, #0f172a 100%)",
    color: "#f1f5f9",
    padding: "0",
    borderRadius: "16px",
    boxShadow: "0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(251,191,36,0.1), 0 0 20px rgba(251,191,36,0.05)",
    animation: "ss-review-glow 5s ease-in-out infinite",
    fontFamily: "system-ui, -apple-system, sans-serif",
    fontSize: "13px",
    opacity: "0",
    transform: "translateY(20px) scale(0.95)",
    transition: "all 0.4s cubic-bezier(0.16, 1, 0.3, 1)",
    overflow: "hidden",
    maxWidth: "340px",
    position: "relative",
    backdropFilter: "blur(16px)"
  });

  // Top shimmer border
  const shimmer = document.createElement("div");
  Object.assign(shimmer.style, {
    height: "2px",
    background: "linear-gradient(90deg, transparent, rgba(251,191,36,0.6), rgba(14,165,233,0.6), transparent)",
    backgroundSize: "200% 100%",
    animation: "ss-review-shimmer 5s linear infinite"
  });

  const content = document.createElement("div");
  Object.assign(content.style, {
    padding: "16px 18px",
    display: "flex",
    flexDirection: "column",
    gap: "12px"
  });

  // Header row with icon + text
  const header = document.createElement("div");
  Object.assign(header.style, {
    display: "flex",
    alignItems: "center",
    gap: "12px"
  });

  const icon = document.createElement("div");
  Object.assign(icon.style, {
    width: "38px",
    height: "38px",
    borderRadius: "12px",
    background: "linear-gradient(135deg, rgba(251,191,36,0.15) 0%, rgba(245,158,11,0.08) 100%)",
    border: "1px solid rgba(251,191,36,0.15)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: "0",
    animation: "ss-star-spin 5s ease-in-out infinite"
  });
  const reviewImg = document.createElement("img");
  reviewImg.src = chrome.runtime.getURL("icons/icon-128.png");
  reviewImg.width = 26;
  reviewImg.height = 26;
  reviewImg.onerror = () => { reviewImg.style.display = "none"; };
  Object.assign(reviewImg.style, { display: "block" });
  icon.appendChild(reviewImg);

  const textWrap = document.createElement("div");
  Object.assign(textWrap.style, { flex: "1", minWidth: "0" });

  const title = document.createElement("div");
  Object.assign(title.style, {
    fontWeight: "700",
    fontSize: "14px",
    letterSpacing: "-0.01em",
    marginBottom: "2px"
  });

  const milestoneText = milestone >= 1000
    ? (milestone / 1000).toLocaleString() + "K"
    : milestone.toLocaleString();
  const milestoneSpan = document.createElement("span");
  milestoneSpan.style.cssText = "background:linear-gradient(135deg,#fbbf24,#f59e0b);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text";
  milestoneSpan.textContent = milestoneText;
  title.appendChild(milestoneSpan);
  title.appendChild(document.createTextNode(" " + t("label_secrets_protected")));

  const sub = document.createElement("div");
  Object.assign(sub.style, {
    fontSize: "11px",
    color: "#64748b",
    fontWeight: "500",
    lineHeight: "1.4"
  });
  sub.textContent = milestone >= 100
    ? t("review_trusted", [total.toLocaleString()])
    : t("review_loving_it");

  textWrap.appendChild(title);
  textWrap.appendChild(sub);
  header.appendChild(icon);
  header.appendChild(textWrap);

  // Close button
  const closeBtn = document.createElement("button");
  Object.assign(closeBtn.style, {
    position: "absolute",
    top: "10px",
    right: "10px",
    width: "22px",
    height: "22px",
    borderRadius: "6px",
    background: "rgba(255,255,255,0.06)",
    border: "none",
    color: "#475569",
    fontSize: "11px",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    transition: "all 0.2s ease",
    padding: "0",
    lineHeight: "1"
  });
  closeBtn.textContent = "\u2715";
  closeBtn.setAttribute("aria-label", t("toast_dismiss"));
  keepEditorFocus(closeBtn);
  closeBtn.onmouseenter = () => { closeBtn.style.background = "rgba(255,255,255,0.12)"; closeBtn.style.color = "#94a3b8"; };
  closeBtn.onmouseleave = () => { closeBtn.style.background = "rgba(255,255,255,0.06)"; closeBtn.style.color = "#475569"; };
  closeBtn.addEventListener("click", () => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(16px) scale(0.95)";
    setTimeout(() => toast.remove(), 300);
  });

  // Button row
  const btnRow = document.createElement("div");
  Object.assign(btnRow.style, {
    display: "flex",
    gap: "8px"
  });

  const rateBtn = document.createElement("a");
  rateBtn.href = "https://chromewebstore.google.com/detail/secret-sanitizer/genolcmpopiemhpbdnhkaefllchgekja/reviews";
  rateBtn.target = "_blank";
  rateBtn.rel = "noopener noreferrer"; // the chat's address stays out of the Web Store's logs
  Object.assign(rateBtn.style, {
    flex: "1",
    padding: "10px 16px",
    background: "linear-gradient(135deg, #f59e0b 0%, #eab308 50%, #f59e0b 100%)",
    backgroundSize: "200% 200%",
    color: "#0f172a",
    border: "none",
    borderRadius: "10px",
    fontSize: "12px",
    fontWeight: "700",
    cursor: "pointer",
    textAlign: "center",
    textDecoration: "none",
    transition: "all 0.25s ease",
    position: "relative",
    overflow: "hidden",
    letterSpacing: "0.02em",
    boxShadow: "0 4px 14px rgba(245,158,11,0.25)"
  });
  rateBtn.textContent = "\u2605 " + t("review_rate");
  keepEditorFocus(rateBtn);
  rateBtn.onmouseenter = () => { rateBtn.style.transform = "translateY(-1px)"; rateBtn.style.boxShadow = "0 6px 20px rgba(245,158,11,0.35)"; };
  rateBtn.onmouseleave = () => { rateBtn.style.transform = "translateY(0)"; rateBtn.style.boxShadow = "0 4px 14px rgba(245,158,11,0.25)"; };
  rateBtn.addEventListener("click", () => {
    safeStorageSet({ reviewDone: true });
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  });

  const laterBtn = document.createElement("button");
  Object.assign(laterBtn.style, {
    padding: "10px 16px",
    background: "rgba(255,255,255,0.06)",
    border: "1px solid rgba(255,255,255,0.08)",
    color: "#64748b",
    borderRadius: "10px",
    fontSize: "12px",
    fontWeight: "500",
    cursor: "pointer",
    transition: "all 0.2s ease"
  });
  laterBtn.textContent = t("review_later");
  keepEditorFocus(laterBtn);
  laterBtn.onmouseenter = () => { laterBtn.style.background = "rgba(255,255,255,0.1)"; laterBtn.style.color = "#94a3b8"; };
  laterBtn.onmouseleave = () => { laterBtn.style.background = "rgba(255,255,255,0.06)"; laterBtn.style.color = "#64748b"; };
  laterBtn.addEventListener("click", () => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(16px) scale(0.95)";
    setTimeout(() => toast.remove(), 300);
  });

  btnRow.appendChild(rateBtn);
  btnRow.appendChild(laterBtn);

  content.appendChild(header);
  content.appendChild(btnRow);

  toast.appendChild(shimmer);
  toast.appendChild(content);
  toast.appendChild(closeBtn);
  mountToast(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0) scale(1)";
  });

  // Auto-dismiss after 20 seconds
  setTimeout(() => {
    if (toast.parentNode) {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(16px) scale(0.95)";
      setTimeout(() => toast.remove(), 300);
    }
  }, 20000);
}

// ==================== MILESTONE CELEBRATION ====================

function showMilestoneCelebration(milestone) {
  // Remove any existing celebration
  const existing = document.getElementById("ss-milestone-toast");
  if (existing) existing.remove();

  // Inject keyframes once
  if (!document.getElementById("ss-milestone-keyframes")) {
    const style = document.createElement("style");
    style.id = "ss-milestone-keyframes";
    style.textContent = `
      @keyframes ss-milestone-border {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
      }
      @keyframes ss-milestone-glow {
        0%, 100% { box-shadow: 0 8px 40px rgba(0,0,0,0.4), 0 0 30px rgba(14,165,233,0.08), inset 0 1px 0 rgba(255,255,255,0.06); }
        50% { box-shadow: 0 12px 48px rgba(0,0,0,0.5), 0 0 40px rgba(14,165,233,0.15), inset 0 1px 0 rgba(255,255,255,0.08); }
      }
      @keyframes ss-trophy-bounce {
        0%, 100% { transform: scale(1) rotate(0deg); }
        15% { transform: scale(1.2) rotate(-8deg); }
        30% { transform: scale(1.15) rotate(6deg); }
        45% { transform: scale(1.1) rotate(-4deg); }
        60% { transform: scale(1.05) rotate(2deg); }
        75% { transform: scale(1.02) rotate(-1deg); }
      }
      @keyframes ss-count-up {
        0% { opacity: 0; transform: translateY(8px) scale(0.9); }
        100% { opacity: 1; transform: translateY(0) scale(1); }
      }
      @keyframes ss-confetti-1 { 0% { transform: translateY(0) rotate(0); opacity: 1; } 100% { transform: translateY(-40px) translateX(15px) rotate(180deg); opacity: 0; } }
      @keyframes ss-confetti-2 { 0% { transform: translateY(0) rotate(0); opacity: 1; } 100% { transform: translateY(-35px) translateX(-12px) rotate(-150deg); opacity: 0; } }
      @keyframes ss-confetti-3 { 0% { transform: translateY(0) rotate(0); opacity: 1; } 100% { transform: translateY(-45px) translateX(8px) rotate(200deg); opacity: 0; } }
    `;
    document.head.appendChild(style);
  }

  // Outer wrapper for the gradient border effect
  const wrapper = document.createElement("div");
  wrapper.id = "ss-milestone-toast";
  wrapper.setAttribute("role", "alert");
  Object.assign(wrapper.style, {
    padding: "1.5px",
    borderRadius: "16px",
    background: "linear-gradient(135deg, #0ea5e9, #06b6d4, #818cf8, #fbbf24, #0ea5e9)",
    backgroundSize: "300% 300%",
    animation: "ss-milestone-border 6s ease infinite, ss-milestone-glow 5s ease-in-out infinite",
    opacity: "0",
    transform: "translateY(12px) scale(0.9)",
    transition: "all 0.5s cubic-bezier(0.16, 1, 0.3, 1)",
    maxWidth: "340px",
    pointerEvents: "none"
  });

  const toast = document.createElement("div");
  Object.assign(toast.style, {
    background: "linear-gradient(145deg, #0f172a 0%, #1e293b 40%, #0f172a 100%)",
    color: "#f1f5f9",
    borderRadius: "15px",
    padding: "18px 20px",
    fontFamily: "system-ui, -apple-system, sans-serif",
    display: "flex",
    alignItems: "center",
    gap: "14px",
    position: "relative",
    overflow: "hidden"
  });

  // Subtle radial glow behind the icon
  const bgGlow = document.createElement("div");
  Object.assign(bgGlow.style, {
    position: "absolute",
    top: "-20px",
    left: "-10px",
    width: "80px",
    height: "80px",
    background: "radial-gradient(circle, rgba(14,165,233,0.12) 0%, transparent 70%)",
    pointerEvents: "none"
  });

  // Trophy icon with bounce
  const iconWrap = document.createElement("div");
  Object.assign(iconWrap.style, {
    position: "relative",
    flexShrink: "0"
  });

  const icon = document.createElement("div");
  const _sid2 = _ssIconId++;
  Object.assign(icon.style, {
    width: "42px",
    height: "42px",
    borderRadius: "14px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    animation: "ss-trophy-bounce 1s ease-out"
  });
  const _svgMile = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  _svgMile.setAttribute("width", "34");
  _svgMile.setAttribute("height", "34");
  _svgMile.setAttribute("viewBox", "0 0 24 24");
  _svgMile.setAttribute("fill", "none");
  const _defs2 = document.createElementNS("http://www.w3.org/2000/svg", "defs");
  const _grad2 = document.createElementNS("http://www.w3.org/2000/svg", "linearGradient");
  _grad2.setAttribute("id", `ss-mg${_sid2}`);
  _grad2.setAttribute("x1", "0"); _grad2.setAttribute("y1", "0");
  _grad2.setAttribute("x2", "1"); _grad2.setAttribute("y2", "1");
  const _stop2a = document.createElementNS("http://www.w3.org/2000/svg", "stop");
  _stop2a.setAttribute("offset", "0%"); _stop2a.setAttribute("stop-color", "#0ea5e9");
  const _stop2b = document.createElementNS("http://www.w3.org/2000/svg", "stop");
  _stop2b.setAttribute("offset", "100%"); _stop2b.setAttribute("stop-color", "#818cf8");
  _grad2.appendChild(_stop2a); _grad2.appendChild(_stop2b);
  _defs2.appendChild(_grad2); _svgMile.appendChild(_defs2);
  const _mp1 = document.createElementNS("http://www.w3.org/2000/svg", "path");
  _mp1.setAttribute("d", "M12 2L4 5.5V11c0 5.25 3.4 10.2 8 11.5 4.6-1.3 8-6.25 8-11.5V5.5L12 2z");
  _mp1.setAttribute("fill", `url(#ss-mg${_sid2})`);
  _mp1.setAttribute("stroke", "#94a3b8"); _mp1.setAttribute("stroke-width", "0.8");
  const _mp2 = document.createElementNS("http://www.w3.org/2000/svg", "path");
  _mp2.setAttribute("d", "M12 8l1.12 2.27 2.5.36-1.81 1.77.43 2.5L12 13.77 9.76 14.9l.43-2.5-1.81-1.77 2.5-.36L12 8z");
  _mp2.setAttribute("fill", "#fff");
  _svgMile.appendChild(_mp1); _svgMile.appendChild(_mp2);
  icon.appendChild(_svgMile);

  // Mini confetti particles
  const confettiColors = ["#fbbf24", "#0ea5e9", "#818cf8"];
  const confettiAnims = ["ss-confetti-1", "ss-confetti-2", "ss-confetti-3"];
  for (let i = 0; i < 3; i++) {
    const particle = document.createElement("div");
    Object.assign(particle.style, {
      position: "absolute",
      width: "4px",
      height: "4px",
      borderRadius: "50%",
      background: confettiColors[i],
      top: "8px",
      left: `${14 + i * 7}px`,
      animation: `${confettiAnims[i]} 0.8s ease-out ${0.1 + i * 0.15}s forwards`,
      opacity: "0",
      pointerEvents: "none"
    });
    // Reset opacity for animation start
    particle.style.opacity = "1";
    iconWrap.appendChild(particle);
  }

  iconWrap.appendChild(icon);

  // Text content
  const textWrap = document.createElement("div");
  Object.assign(textWrap.style, { flex: "1", minWidth: "0" });

  const count = document.createElement("div");
  Object.assign(count.style, {
    fontWeight: "800",
    fontSize: "16px",
    letterSpacing: "-0.02em",
    marginBottom: "3px",
    animation: "ss-count-up 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.2s both"
  });

  const mText = milestone >= 1000
    ? (milestone / 1000).toLocaleString() + "K"
    : milestone.toLocaleString();
  const mSpan = document.createElement("span");
  mSpan.style.cssText = "background:linear-gradient(135deg,#38bdf8,#06b6d4,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text";
  mSpan.textContent = mText;
  const protSpan = document.createElement("span");
  protSpan.style.color = "#e2e8f0";
  protSpan.textContent = " " + t("label_secrets_protected");
  count.appendChild(mSpan);
  count.appendChild(protSpan);

  const sub = document.createElement("div");
  Object.assign(sub.style, {
    fontSize: "11px",
    color: "#64748b",
    fontWeight: "500",
    animation: "ss-count-up 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.35s both"
  });

  // Dynamic sub-text based on milestone tier
  const subTiers = [100000, 50000, 10000, 5000, 1000, 500, 100];
  const tier = subTiers.find(k => milestone >= k);
  sub.textContent = tier ? t("milestone_tier", [t(`milestone_${tier}`)]) : t("milestone_reached");

  textWrap.appendChild(count);
  textWrap.appendChild(sub);

  toast.appendChild(bgGlow);
  toast.appendChild(iconWrap);
  toast.appendChild(textWrap);
  wrapper.appendChild(toast);
  mountToast(wrapper);

  // Animate in
  requestAnimationFrame(() => {
    wrapper.style.opacity = "1";
    wrapper.style.transform = "translateY(0) scale(1)";
  });

  // Auto-dismiss after 5 seconds
  setTimeout(() => {
    if (wrapper.parentNode) {
      wrapper.style.opacity = "0";
      wrapper.style.transform = "translateY(8px) scale(0.95)";
      setTimeout(() => wrapper.remove(), 400);
    }
  }, 5000);
}

// ==================== MESSAGE HANDLERS ====================

chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  try {
    if (request.action === "milestone") {
      showMilestoneCelebration(request.milestone);
      sendResponse({ success: true });
    } else {
      sendResponse({ success: false, error: "Unknown action" });
    }
  } catch (err) {
    console.warn("Message handler error:", err);
    sendResponse({ success: false, error: err.message });
  }
  // sendResponse is always called synchronously above — return false to close the message channel
  return false;
});