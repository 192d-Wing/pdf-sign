// Service worker: relays messages from the content script to the native
// messaging host. Chrome spawns the host per message (sendNativeMessage),
// sends one JSON message, and returns its one JSON response.
const HOST_NAME = 'com.pdfsign.bridge';

// Must stay in sync with content_scripts.matches in manifest.json. The
// manifest already limits where the content script runs; this check keeps
// a future broadening of `matches` from silently widening card access.
// NIST 800-53r5 AC-3 (access enforcement): only allowlisted web origins
// may reach the native host and therefore the smart card.
const ALLOWED_ORIGINS = ['http://127.0.0.1:8080/', 'http://localhost:8080/'];

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!sender.url || !ALLOWED_ORIGINS.some((origin) => sender.url.startsWith(origin))) {
    sendResponse({ error: `origin not allowed: ${sender.url || 'unknown'}` });
    return;
  }
  chrome.runtime.sendNativeMessage(HOST_NAME, message, (response) => {
    if (chrome.runtime.lastError) {
      sendResponse({ error: `native host: ${chrome.runtime.lastError.message}` });
    } else {
      sendResponse(response);
    }
  });
  return true; // keep sendResponse alive for the async reply
});
