// Config
const CONFIG = {
  cacheSize: 100, // Cache last N text samples
  minTextLength: 6, // Skip processing very short text
  gestureWindowMs: 5000, // Smart Restore: max age of the trusted click/keypress behind a copy
  contextMenuWindowMs: 60000 // Smart Restore: right-click → "Copy" may take a while
};

// Unique ID counter for SVG gradient IDs (prevents DOM collisions when multiple toasts coexist)
let _ssIconId = 0;

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

// Performance cache
const patternCache = new Map();

// Patterns live in patterns.js and the engine in detector.js (both shared with popup.js).
// Start with every pattern enabled so a paste that lands before settings load is
// over-masked rather than leaked.
let COMPILED_PATTERNS = compilePatterns(SHARED_PATTERNS);

async function loadPatternSettings() {
  try {
    const { disabledPatterns = [] } = await safeStorageGet("disabledPatterns");
    COMPILED_PATTERNS = compilePatterns(SHARED_PATTERNS, disabledPatterns);
    patternCache.clear();
  } catch (_) {
    // Keep the current (all-enabled) patterns
  }
}

loadPatternSettings();
if (isExtensionContextValid()) {
  // Apply pattern toggles from the popup without requiring a page reload
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.disabledPatterns) loadPatternSettings();
  });
}

// FNV-1a hash for cache keys — fast, low-collision string hash
// For large strings (>2KB), sample first+last 512 chars + length for speed.
// Cache hits are still verified by full text === comparison.
function fnv1aHash(str) {
  let hash = 0x811c9dc5; // FNV offset basis
  let source = str;
  if (str.length > 2048) {
    source = str.slice(0, 512) + str.slice(-512) + str.length;
  }
  for (let i = 0; i < source.length; i++) {
    hash ^= source.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0; // FNV prime, keep as uint32
  }
  return hash.toString(36);
}

// Detect + mask with caching. Returns { maskedText, replacements, partial }.
// Every paste gets a random id baked into its placeholders ([OPENAI_KEY_k3f9_0]) so
// placeholders from different pastes never collide.
function sanitizeText(text) {
  if (!text || text.length < CONFIG.minTextLength) {
    return { maskedText: text, replacements: [], partial: false };
  }

  const cacheKey = fnv1aHash(text);
  const cached = patternCache.get(cacheKey);
  if (cached && cached.text === text) {
    // Move to end for LRU eviction (delete + re-insert)
    patternCache.delete(cacheKey);
    patternCache.set(cacheKey, cached);
    return cached.result;
  }

  const { matches, partial } = findSecrets(text, COMPILED_PATTERNS);
  const pasteId = newPasteId();
  const { maskedText, replacements } = maskText(text, matches, (label, i) => makePlaceholder(label, pasteId, i));
  const result = { maskedText, replacements, partial };

  if (patternCache.size >= CONFIG.cacheSize) {
    patternCache.delete(patternCache.keys().next().value);
  }
  patternCache.set(cacheKey, { text, result });
  return result;
}

// The vault lives in the background worker's memory-only storage (chrome.storage.session):
// never written to disk and never readable by the page. Stats are updated there too.
async function saveToVault(replacements) {
  const res = await sendToBackground({ action: "vault:save", replacements });
  if (!res?.ok) throw new Error(res?.error || "vault unavailable");
}

// Returns the bottom offset (px) needed to stack a new toast above all visible SS toasts
function getToastStackOffset() {
  let offset = 20;
  document.querySelectorAll(
    '.secret-sanitizer-toast, .secret-sanitizer-clean-toast, #ss-milestone-toast, .secret-sanitizer-review-toast'
  ).forEach(t => {
    const h = t.offsetHeight;
    if (h > 0) offset += h + 12;
  });
  return offset;
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
    position: "fixed",
    bottom: "20px",
    right: "20px",
    background: "#1e293b",
    color: "#f1f5f9",
    padding: "0",
    borderRadius: "12px",
    boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
    zIndex: "2147483647",
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
  document.body.appendChild(toast);

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

// Subtle "clean" toast - confirms extension is active even when no secrets found
function showCleanToast() {
  if (!document.body) return;
  // Don't spam - throttle to once per 30 seconds
  if (showCleanToast._lastShown && Date.now() - showCleanToast._lastShown < 30000) return;
  showCleanToast._lastShown = Date.now();

  document.querySelectorAll(".secret-sanitizer-clean-toast").forEach(t => t.remove());

  const toast = document.createElement("div");
  toast.className = "secret-sanitizer-clean-toast";
  toast.setAttribute("role", "alert");

  Object.assign(toast.style, {
    position: "fixed",
    bottom: "20px",
    right: "20px",
    background: "#1e293b",
    color: "#94a3b8",
    padding: "0",
    borderRadius: "12px",
    boxShadow: "0 4px 16px rgba(0,0,0,0.2)",
    zIndex: "2147483647",
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
  cleanMsg.textContent = "Scanned \u2014 no secrets found";
  content.appendChild(iconWrap);
  content.appendChild(cleanMsg);
  toast.appendChild(content);
  document.body.appendChild(toast);

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

// Smart toast with secret types and Undo
function showSmartToast(secretTypes, onUndo, partial = false) {
  if (!document.body) return;
  document.querySelectorAll(".secret-sanitizer-toast").forEach(t => t.remove());

  const toast = document.createElement("div");
  toast.className = "secret-sanitizer-toast";
  toast.setAttribute("role", "alert");

  const types = [...new Set(secretTypes)];
  const typeDisplay = types.slice(0, 2).join(", ") + (types.length > 2 ? ` +${types.length - 2}` : "");

  Object.assign(toast.style, {
    position: "fixed",
    bottom: "80px",
    right: "16px",
    background: "linear-gradient(135deg, #1e293b 0%, #182030 100%)",
    color: "#f1f5f9",
    padding: "0",
    borderRadius: "12px",
    border: "1px solid rgba(255,255,255,0.07)",
    boxShadow: "0 8px 24px rgba(0,0,0,0.35), 0 0 0 1px rgba(14,165,233,0.08)",
    zIndex: "2147483647",
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
  label.textContent = `${secretTypes.length} secret${secretTypes.length > 1 ? 's' : ''} masked` +
    (partial ? " \u00b7 partial scan" : "");
  label.title = partial
    ? `${typeDisplay} \u2014 very large paste: only known key formats were checked, review before sending`
    : typeDisplay; // full type list on hover

  content.appendChild(icon);
  content.appendChild(label);

  // Auto-dismiss after 5 seconds (longer to allow undo)
  // Declared before undo button so the onclick closure can reference it
  let dismissTimeout;

  // Undo button (if callback provided)
  if (onUndo) {
    const undoBtn = document.createElement("button");
    Object.assign(undoBtn.style, {
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
    undoBtn.textContent = "Undo";
    // Prevent button from stealing focus away from the editor
    undoBtn.addEventListener("mousedown", (e) => e.preventDefault());
    undoBtn.onmouseenter = () => {
      undoBtn.style.background = "rgba(255,255,255,0.15)";
      undoBtn.style.color = "#f1f5f9";
    };
    undoBtn.onmouseleave = () => {
      undoBtn.style.background = "rgba(255,255,255,0.1)";
      undoBtn.style.color = "#94a3b8";
    };
    undoBtn.onclick = (e) => {
      // Undo puts plaintext secrets back into the page. The toast lives in the page DOM,
      // so only honour real user clicks — page script can't forge isTrusted.
      if (!e.isTrusted) return;
      e.stopPropagation();
      clearTimeout(dismissTimeout);
      const success = onUndo();
      toast.style.opacity = "0";
      toast.style.transform = "translateY(8px)";
      setTimeout(() => {
        toast.remove();
        showToast(success !== false ? "Restored original text" : "Couldn't restore text", success !== false ? "success" : "error");
      }, 200);
    };
    content.appendChild(undoBtn);
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
  closeBtn.setAttribute("aria-label", "Dismiss");
  closeBtn.addEventListener("mousedown", (e) => e.preventDefault()); // don't steal editor focus
  closeBtn.onmouseenter = () => { closeBtn.style.color = "#cbd5e1"; };
  closeBtn.onmouseleave = () => { closeBtn.style.color = "#64748b"; };
  closeBtn.onclick = (e) => {
    e.stopPropagation();
    clearTimeout(dismissTimeout);
    toast.style.opacity = "0";
    toast.style.transform = "translateY(8px)";
    setTimeout(() => toast.remove(), 200);
  };
  content.appendChild(closeBtn);

  toast.appendChild(content);
  document.body.appendChild(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";
  });

  dismissTimeout = setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(8px)";
    setTimeout(() => toast.remove(), 200);
  }, 5000);

  // Clear timeout if manually dismissed
  toast.addEventListener("click", () => {
    clearTimeout(dismissTimeout);
    toast.style.opacity = "0";
    toast.style.transform = "translateY(8px)";
    setTimeout(() => toast.remove(), 200);
  });
}

// Paste handler — registered at document_start in the window capture phase, so it runs
// before any listener the page can add and the page never sees the unmasked paste.
window.addEventListener("paste", (e) => {
  // Synthetic paste events are built by page script from data the page already has
  if (!e.isTrusted) return;

  const clipboardText = e.clipboardData?.getData("text");
  if (!clipboardText || clipboardText.length < CONFIG.minTextLength) return;

  const { maskedText, replacements, partial } = sanitizeText(clipboardText);
  if (replacements.length === 0) {
    if (partial) {
      showToast("Very large paste \u2014 only known key formats were checked", "warning");
    } else if (clipboardText.length >= 200 || /\S{20,}/.test(clipboardText)) {
      showCleanToast();
    }
    return;
  }

  e.preventDefault();
  e.stopImmediatePropagation();

  const target = document.activeElement;

  // Async save (don't block UI). Undo works without it; Smart Restore needs it.
  saveToVault(replacements).catch(() => {
    showToast("Couldn't save for Smart Restore \u2014 secrets were still masked", "warning");
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

    // Fallback: Selection API (no undo stack integration)
    if (!inserted) {
      try {
        const sel = window.getSelection();
        if (sel.rangeCount > 0) {
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
      const newValue = value.substring(0, start) + maskedText + value.substring(end);

      // Use native setter for React/framework compatibility
      const nativeSetter = Object.getOwnPropertyDescriptor(
        Object.getPrototypeOf(target), 'value'
      )?.set;
      if (nativeSetter) {
        nativeSetter.call(target, newValue);
      } else {
        target.value = newValue;
      }
      const cursorPos = start + maskedText.length;
      target.setSelectionRange(cursorPos, cursorPos);
      target.dispatchEvent(new Event('input', { bubbles: true }));
      target.dispatchEvent(new Event('change', { bubbles: true }));
      inserted = true;
    } catch (err) {
      console.warn("[SecretSanitizer] Failed to insert masked text into textarea:", err);
    }
  }

  if (inserted) {
    // Extract secret types from placeholders (e.g., [OPENAI_KEY_k3f9_0] -> OPENAI_KEY)
    const secretTypes = replacements.map(([placeholder]) => placeholderLabel(placeholder) || "SECRET");

    // Undo: replace each placeholder with its original secret individually.
    // This is more robust than replacing the entire maskedText at once, because
    // rich text editors (Lexical, ProseMirror) often split/reformat inserted text.
    const handleUndo = () => {
      try {
        if (target.isContentEditable) {
          target.focus();
          let restored = 0;

          // Replace each placeholder individually in reverse order (last first)
          // so earlier positions aren't shifted by earlier replacements.
          // Optimisation: collect text nodes once; fall back to a fresh walk only
          // when execCommand has restructured the DOM (e.g. split a shared node).
          const cachedNodes = [];
          {
            const initWalker = document.createTreeWalker(target, NodeFilter.SHOW_TEXT);
            let n;
            while ((n = initWalker.nextNode())) cachedNodes.push(n);
          }

          for (let i = replacements.length - 1; i >= 0; i--) {
            const [placeholder, original] = replacements[i];
            let found = false;

            // Fast path: search cached text nodes (O(1) amortised across calls)
            for (const node of cachedNodes) {
              if (!target.contains(node)) continue;
              const idx = node.textContent.indexOf(placeholder);
              if (idx !== -1) {
                const range = document.createRange();
                range.setStart(node, idx);
                range.setEnd(node, idx + placeholder.length);
                const sel = window.getSelection();
                sel.removeAllRanges();
                sel.addRange(range);
                document.execCommand('insertText', false, original);
                restored++;
                found = true;
                break;
              }
            }

            // Slow-path fallback: fresh walk when execCommand restructured the DOM
            // (e.g. two placeholders shared one text node and it was split)
            if (!found) {
              const freshWalker = document.createTreeWalker(target, NodeFilter.SHOW_TEXT);
              let node;
              while ((node = freshWalker.nextNode())) {
                const idx = node.textContent.indexOf(placeholder);
                if (idx !== -1) {
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
            }
          }

          // If no individual placeholders found, try full-text fallback
          if (restored === 0) {
            document.execCommand('undo');
          }
          target.focus();
          return restored > 0;
        } else if (target.value !== undefined) {
          target.focus();

          // Replace each placeholder individually in the value
          let currentValue = target.value;
          let restored = 0;

          for (const [placeholder, original] of replacements) {
            const idx = currentValue.indexOf(placeholder);
            if (idx !== -1) {
              currentValue = currentValue.substring(0, idx) + original + currentValue.substring(idx + placeholder.length);
              restored++;
            }
          }

          if (restored > 0) {
            // Use native setter for React/framework compatibility
            const nativeSetter = Object.getOwnPropertyDescriptor(
              Object.getPrototypeOf(target), 'value'
            )?.set;
            if (nativeSetter) {
              nativeSetter.call(target, currentValue);
            } else {
              target.value = currentValue;
            }
          } else {
            // Full-text fallback: replace entire maskedText block
            const idx = currentValue.indexOf(maskedText);
            if (idx !== -1) {
              target.value = currentValue.substring(0, idx) + clipboardText + currentValue.substring(idx + maskedText.length);
            }
          }
          target.dispatchEvent(new Event('input', { bubbles: true }));
          target.dispatchEvent(new Event('change', { bubbles: true }));
          return restored > 0;
        }
        return false;
      } catch (_) {
        return false;
      }
    };

    showSmartToast(secretTypes, handleUndo, partial);

    // Check if we should prompt for a review (delayed to not overlap)
    setTimeout(() => checkReviewPrompt(), 6000);
  } else {
    showToast("Insertion failed! Try pasting again.", "error");
  }
}, true);

// ==================== SMART RESTORE (copy) ====================
//
// Security model: the page (and any script running in it) must never obtain original
// secrets. Restored text is therefore only ever written to the system clipboard from this
// isolated world via navigator.clipboard.writeText() — never through DOM events, the DOM,
// or e.clipboardData.setData() (the page's own copy listeners could getData() it).
// A restore also requires a recent *trusted* user gesture, which page script cannot forge,
// and is refused on sites the user has allowed to read the clipboard.

let _lastGestureAt = 0;
let _lastContextMenuAt = 0;
const markUserGesture = (e) => { if (e.isTrusted) _lastGestureAt = Date.now(); };
window.addEventListener("pointerdown", markUserGesture, true);
window.addEventListener("keydown", markUserGesture, true);
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
  if (_siteCanReadClipboard) {
    showToast("Smart Restore is off here — this site can read your clipboard", "warning");
    return false;
  }
  return true;
}

function showRestoreToast(restoredCount, expiredCount) {
  if (expiredCount > 0) {
    showToast(
      `${restoredCount} secret${restoredCount !== 1 ? 's' : ''} restored · ${expiredCount} expired`,
      'warning'
    );
  } else {
    showToast(
      `${restoredCount} secret${restoredCount !== 1 ? 's' : ''} restored in clipboard`,
      'info'
    );
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
      const restored = text.replace(new RegExp(PLACEHOLDER_SOURCE, "g"), (m) => values[m] ?? m);
      await navigator.clipboard.writeText(restored);
      showRestoreToast(resolved.length, tokens.length - resolved.length);
    } else if (fallbackText !== undefined) {
      await navigator.clipboard.writeText(fallbackText);
    }
  } catch (_) {
    showToast("Couldn't restore secrets to the clipboard", "error");
  }
}

// Manual copy (Ctrl/Cmd+C, right-click → Copy) and page copy buttons that use
// execCommand('copy'). The browser/page completes the normal (masked) copy first; the
// async write below then replaces it with the restored text.
document.addEventListener("copy", (e) => {
  if (!e.isTrusted) return; // synthetic copy events carry no real clipboard action

  // Textarea elements keep their own selection, separate from window.getSelection()
  const t = e.target;
  const selected = (t && t.tagName === "TEXTAREA")
    ? t.value.substring(t.selectionStart || 0, t.selectionEnd ?? t.value.length)
    : (window.getSelection()?.toString() || "");
  if (!selected || !PLACEHOLDER_TEST_RE.test(selected)) return;

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
  if (typeof text !== "string" || !PLACEHOLDER_TEST_RE.test(text)) return;
  if (!hasRecentUserGesture() || !canSmartRestore()) return;

  e.preventDefault(); // tells the MAIN-world wrapper we own this clipboard write
  restoreToClipboard(text, text);
});

// ==================== REVIEW PROMPT ====================

const REVIEW_MILESTONES = [10, 50, 100, 500, 1000, 5000, 10000];

async function checkReviewPrompt() {
  try {
    const { stats = {}, reviewLastShownAt = 0 } = await safeStorageGet(["stats", "reviewLastShownAt"]);
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
    position: "fixed",
    bottom: getToastStackOffset() + "px",
    right: "20px",
    background: "linear-gradient(145deg, #0f172a 0%, #1e293b 50%, #0f172a 100%)",
    color: "#f1f5f9",
    padding: "0",
    borderRadius: "16px",
    boxShadow: "0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(251,191,36,0.1), 0 0 20px rgba(251,191,36,0.05)",
    animation: "ss-review-glow 5s ease-in-out infinite",
    zIndex: "2147483647",
    fontFamily: "system-ui, -apple-system, sans-serif",
    fontSize: "13px",
    opacity: "0",
    transform: "translateY(20px) scale(0.95)",
    transition: "all 0.4s cubic-bezier(0.16, 1, 0.3, 1)",
    overflow: "hidden",
    maxWidth: "340px",
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
  title.appendChild(document.createTextNode(" secrets protected"));

  const sub = document.createElement("div");
  Object.assign(sub.style, {
    fontSize: "11px",
    color: "#64748b",
    fontWeight: "500",
    lineHeight: "1.4"
  });
  sub.textContent = milestone >= 100
    ? "Trusted with " + total.toLocaleString() + " secrets. Help others stay safe."
    : "Loving it? A quick rating goes a long way.";

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
  rateBtn.rel = "noopener";
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
  rateBtn.textContent = "\u2605 Rate on Chrome Store";
  rateBtn.onmouseenter = () => { rateBtn.style.transform = "translateY(-1px)"; rateBtn.style.boxShadow = "0 6px 20px rgba(245,158,11,0.35)"; };
  rateBtn.onmouseleave = () => { rateBtn.style.transform = "translateY(0)"; rateBtn.style.boxShadow = "0 4px 14px rgba(245,158,11,0.25)"; };
  rateBtn.addEventListener("click", () => {
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
  laterBtn.textContent = "Later";
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
  document.body.appendChild(toast);

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

  const bottomOffset = getToastStackOffset();

  // Outer wrapper for the gradient border effect
  const wrapper = document.createElement("div");
  wrapper.id = "ss-milestone-toast";
  wrapper.setAttribute("role", "alert");
  Object.assign(wrapper.style, {
    position: "fixed",
    bottom: bottomOffset + "px",
    right: "20px",
    padding: "1.5px",
    borderRadius: "16px",
    background: "linear-gradient(135deg, #0ea5e9, #06b6d4, #818cf8, #fbbf24, #0ea5e9)",
    backgroundSize: "300% 300%",
    animation: "ss-milestone-border 6s ease infinite, ss-milestone-glow 5s ease-in-out infinite",
    zIndex: "2147483647",
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
  protSpan.textContent = " secrets protected";
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
  const subTexts = {
    100: "Getting started!",
    500: "Privacy champion",
    1000: "Security pro",
    5000: "Elite protector",
    10000: "Legendary guardian",
    50000: "Unstoppable force",
    100000: "God-tier security"
  };
  const nearestSub = Object.keys(subTexts).reverse().find(k => milestone >= Number(k));
  sub.textContent = nearestSub ? `Milestone \u2022 ${subTexts[nearestSub]}` : "Milestone reached";

  textWrap.appendChild(count);
  textWrap.appendChild(sub);

  toast.appendChild(bgGlow);
  toast.appendChild(iconWrap);
  toast.appendChild(textWrap);
  wrapper.appendChild(toast);
  document.body.appendChild(wrapper);

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