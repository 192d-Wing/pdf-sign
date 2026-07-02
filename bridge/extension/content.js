// Content script: bridges window.postMessage on the pdf-sign page to the
// extension's service worker (which talks to the native host).
//
// Page -> bridge:  { type: 'pdfsign-bridge-request', id, cmd, payload }
// Bridge -> page:  { type: 'pdfsign-bridge-response', id, response }
window.addEventListener('message', (event) => {
  if (event.source !== window) return;
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
