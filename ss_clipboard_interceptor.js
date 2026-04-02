// ss_clipboard_interceptor.js — runs in MAIN world (document_start)
// Intercepts programmatic clipboard writes (AI copy buttons) and provides the
// clipboard write side of the Smart Restore feature.
//
// Architecture:
//   1. For manual Ctrl+C / right-click copy:
//      - Captures every copy event to store the event object (_activeCopyEvent)
//      - Listens for '__ss_resolved' dispatched synchronously by the isolated-world
//        copy handler; calls e.clipboardData.setData() from MAIN world (works here,
//        silently fails in isolated world).
//
//   2. For programmatic copy buttons (navigator.clipboard.writeText/write):
//      - Intercepts the call, fires execCommand('copy') on a hidden textarea so
//        the isolated-world copy handler runs and dispatches '__ss_resolved'.
//      - MAIN world's '__ss_resolved' handler then calls e.clipboardData.setData().
//      - No clipboardWrite permission required.
(function () {
  if (window.__ssClipboardInterceptorInstalled) return;
  window.__ssClipboardInterceptorInstalled = true;

  const PLACEHOLDER_RE = /\[[A-Z][A-Z0-9_]+_\d+\]/;

  const _origWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
  const _origWrite     = navigator.clipboard.write.bind(navigator.clipboard);

  // ── Copy-event capture ────────────────────────────────────────────────────
  // Store the active copy event so '__ss_resolved' can call setData() on it.
  // Registered at document_start so it runs before any later-registered listener.
  let _activeCopyEvent = null;

  document.addEventListener('copy', (e) => {
    _activeCopyEvent = e;
    // Safety: clear after event dispatch completes (all listeners have run)
    setTimeout(() => { _activeCopyEvent = null; }, 0);
  }, true); // capture phase = fires before isolated-world listener

  // '__ss_resolved' is dispatched synchronously by the isolated-world copy handler.
  // Calling setData() here (MAIN world) reliably updates the system clipboard.
  document.addEventListener('__ss_resolved', (e) => {
    if (!_activeCopyEvent) return;
    const text = e.detail?.text;
    if (typeof text !== 'string') return;
    _activeCopyEvent.preventDefault();
    _activeCopyEvent.clipboardData.setData('text/plain', text);
    _activeCopyEvent = null; // consumed
  });

  // ── Programmatic-copy interception ────────────────────────────────────────
  // Fire execCommand('copy') on a hidden textarea containing the masked text.
  // This triggers a copy DOM event → isolated world resolves tokens →
  // dispatches '__ss_resolved' → MAIN world's handler above calls setData().
  // All synchronous; user-gesture context is preserved.
  function triggerCopyEvent(text) {
    const prev = document.activeElement;
    const el = document.createElement('textarea');
    el.value = text;
    el.setAttribute('readonly', '');
    el.style.cssText = 'position:fixed;top:-9999px;left:-9999px;width:1px;height:1px;opacity:0;pointer-events:none';
    document.body.appendChild(el);
    el.focus();
    el.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (_) {}
    document.body.removeChild(el);
    // Restore prior focus so the user's editing context is unaffected
    try { if (prev && typeof prev.focus === 'function') prev.focus(); } catch (_) {}
    return ok;
  }

  navigator.clipboard.writeText = function (text) {
    if (text && typeof text === 'string' && PLACEHOLDER_RE.test(text)) {
      if (triggerCopyEvent(text)) return Promise.resolve();
    }
    return _origWriteText(text);
  };

  navigator.clipboard.write = async function (items) {
    // Extract text/plain from ClipboardItems (ChatGPT code-block copy buttons).
    // User activation persists through microtask awaits, so execCommand still works.
    try {
      for (const item of items) {
        if (!item.types.includes('text/plain')) continue;
        const blob = await item.getType('text/plain');
        const text = await blob.text();
        if (PLACEHOLDER_RE.test(text)) {
          if (triggerCopyEvent(text)) return;
          break; // execCommand failed — fall through to original write
        }
      }
    } catch (_) {}
    return _origWrite(items);
  };
})();
