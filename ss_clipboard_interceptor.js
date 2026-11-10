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

  // Plain [OPENAI_KEY_k3f9_0] or Markdown-escaped \[OPENAI\_KEY\_k3f9\_0\] (some copy buttons
  // serialise to Markdown). Mirrors LOOSE_PLACEHOLDER_SOURCE in detector.js.
  const PLACEHOLDER_RE = /\\?\[[A-Z](?:\\?[A-Z0-9_])*\\?_[a-z0-9]{4}\\?_\d+\\?\]/;

  // Copy buttons that put their text on the copy event instead: a copy listener calling
  // e.clipboardData.setData() after execCommand('copy'), often with nothing selected and the
  // event stopped before it reaches the document. That write can't be taken over here, so this
  // only tells the content script what was copied (masked text, one way); it decides whether a
  // trusted copy is in progress and restores afterwards.
  const _origSetData = DataTransfer.prototype.setData;
  DataTransfer.prototype.setData = function (type, data) {
    const result = _origSetData.call(this, type, data);
    try {
      if (typeof data === 'string' && /^text(?:\/plain)?$/i.test(String(type).trim()) && PLACEHOLDER_RE.test(data)) {
        document.dispatchEvent(new CustomEvent('__ss_restore_hint', { detail: data }));
      }
    } catch (_) {
      // Never let the relay break the page's own copy
    }
    return result;
  };

  const clipboard = navigator.clipboard;
  if (!clipboard) return; // insecure context (http://) — no async clipboard API to wrap

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
