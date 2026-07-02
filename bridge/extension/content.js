// Content script: bridges window.postMessage on the pdf-sign page to the
// extension's service worker (which talks to the native host).
//
// Page -> bridge:  { type: 'pdfsign-bridge-request', id, cmd, payload }
// Bridge -> page:  { type: 'pdfsign-bridge-response', id, response }
window.addEventListener('message', (event) => {
  // Accept requests only from this page's own window and origin. The
  // content script is already injected solely on allowlisted origins
  // (manifest matches), and background.js re-checks sender.url — this is
  // the third, in-page layer.
  if (event.source !== window || event.origin !== window.location.origin) return;
  const msg = event.data;
  if (!msg || msg.type !== 'pdfsign-bridge-request') return;

  const request = { cmd: msg.cmd, ...(msg.payload || {}) };
  chrome.runtime.sendMessage(request, (response) => {
    window.postMessage(
      {
        type: 'pdfsign-bridge-response',
        id: msg.id,
        response: response ?? { error: chrome.runtime.lastError?.message || 'no response from extension' },
      },
      window.origin
    );
  });
});
