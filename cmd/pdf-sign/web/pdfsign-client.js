// pdfsign-client: browser SDK for the pdf-sign smart card bridge.
//
// Copy this file into any website that wants smart-card PDF signing. It
// encapsulates the postMessage protocol spoken by the bridge/ extension;
// the page's origin must be listed in the extension's manifest `matches`
// and background.js ALLOWED_ORIGINS.
//
// Usage:
//   import { detectBridge } from './pdfsign-client.js';
//   const bridge = await detectBridge();          // null if not installed
//   const { certificate, thumbprint, warning } = await bridge.getCertificate();
//   // → send `certificate` to your backend, which creates a signing
//   //   session (internal/signing or pdfsign-svc) and returns the digest
//   const signature = await bridge.signDigest(digest, thumbprint);
//   // → send `signature` to your backend, which completes the session
//
// The bridge never sees the document — only a 32-byte digest goes to the
// card, and Windows prompts for the PIN.

const SIGN_TIMEOUT_MS = 120000; // PIN entry can take a while
const PING_TIMEOUT_MS = 1500;

export function createNativeBridge() {
  let seq = 0;
  const pending = new Map();

  window.addEventListener('message', (event) => {
    // Only accept responses posted by our own content script on this exact
    // origin (defense in depth on top of the source===window check).
    if (event.source !== window || event.origin !== window.location.origin) return;
    const msg = event.data;
    if (!msg || msg.type !== 'pdfsign-bridge-response') return;
    const waiter = pending.get(msg.id);
    if (!waiter) return;
    pending.delete(msg.id);
    const resp = msg.response || {};
    resp.error ? waiter.reject(new Error(resp.error)) : waiter.resolve(resp);
  });

  function call(cmd, payload = {}, timeoutMs = SIGN_TIMEOUT_MS) {
    return new Promise((resolve, reject) => {
      const id = ++seq;
      pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (pending.delete(id)) reject(new Error(`bridge timeout (${cmd})`));
      }, timeoutMs);
      window.postMessage({ type: 'pdfsign-bridge-request', id, cmd, payload }, window.origin);
    });
  }

  return {
    name: 'smart card',

    async available() {
      try {
        const r = await call('ping', {}, PING_TIMEOUT_MS);
        return !!r.ok;
      } catch {
        return false;
      }
    },

    // Lists all usable signing certificates on the card/store; the host
    // puts the best candidate first (non-repudiation cert on PIV/CAC).
    async listCertificates() {
      const r = await call('listCertificates');
      return r.certificates || [];
    },

    // Convenience: best certificate, as { certificate, thumbprint, warning }.
    async getCertificate() {
      const certs = await this.listCertificates();
      if (!certs.length) throw new Error('no signing certificates found — is the card inserted?');
      const best = certs[0];
      return {
        certificate: best.certificate,
        thumbprint: best.thumbprint,
        warning: best.warning || '',
      };
    },

    // digestB64: base64 SHA-256 digest from the signing session.
    // Returns the base64 raw signature (PKCS#1 v1.5 for RSA, DER for ECDSA).
    async signDigest(digestB64, thumbprint) {
      const r = await call('signDigest', { thumbprint, digest: digestB64 });
      return r.signature;
    },
  };
}

// Returns a connected bridge, or null when the extension/native host is
// not installed.
export async function detectBridge() {
  const bridge = createNativeBridge();
  return (await bridge.available()) ? bridge : null;
}
