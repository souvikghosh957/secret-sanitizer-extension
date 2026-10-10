// ss_clipboard_interceptor.js — runs in the page's MAIN world (document_start).
// Lets Smart Restore work with AI "copy" buttons, which call navigator.clipboard.writeText()
// or navigator.clipboard.write() from page JavaScript.
//
// SECURITY: this file runs alongside the page's own scripts, so anything it can see the
// page can see too. Information therefore only flows ONE way — page → extension:
//   1. A copy button writes text containing placeholders like [OPENAI_KEY_k3f9_0].
//   2. We dispatch a cancelable '__ss_restore_request' event carrying that (already
//      masked) text. The isolated-world content script decides whether to handle it
//      (it requires a recent trusted user gesture) and cancels the event if it does.
//   3. The content script writes the restored text to the system clipboard itself, from
//      the isolated world. Original secrets are never placed on a DOM event, a DOM node,
//      or anywhere else this world (or the page) can read.
(function () {
  if (window.__ssClipboardInterceptorInstalled) return;
  window.__ssClipboardInterceptorInstalled = true;

  const clipboard = navigator.clipboard;
  if (!clipboard) return; // insecure context (http://) — no async clipboard API to wrap

  const PLACEHOLDER_RE = /\[[A-Z][A-Z0-9_]*_[a-z0-9]{4}_\d+\]/;
  const _origWriteText = clipboard.writeText.bind(clipboard);
  const _origWrite = clipboard.write.bind(clipboard);

  // Returns true when the content script took over the clipboard write.
  function requestRestore(text) {
    const ev = new CustomEvent('__ss_restore_request', { detail: text, cancelable: true });
    return !document.dispatchEvent(ev);
  }

  clipboard.writeText = function (text) {
    if (typeof text === 'string' && PLACEHOLDER_RE.test(text) && requestRestore(text)) {
      return Promise.resolve();
    }
    return _origWriteText(text);
  };

  clipboard.write = async function (items) {
    // Extract text/plain from ClipboardItems (e.g. ChatGPT code-block copy buttons)
    try {
      for (const item of items) {
        if (!item.types.includes('text/plain')) continue;
        const text = await (await item.getType('text/plain')).text();
        if (PLACEHOLDER_RE.test(text) && requestRestore(text)) return;
        break;
      }
    } catch (_) {
      // Unreadable item — fall through to the original write
    }
    return _origWrite(items);
  };
})();
