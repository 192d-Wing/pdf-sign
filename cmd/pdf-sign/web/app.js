// Reference integrator for the pdf-sign signing stack.
//
// All card interaction goes through the SDK (pdfsign-client.js); this file
// only implements the demo approval queue: list items, drive the
// start → sign → finish flow against this app's own backend, and render
// results. Another website would keep this shape and swap the /api/*
// endpoints for its own backend (which in turn calls internal/signing or
// pdfsign-svc).
import { detectBridge } from './pdfsign-client.js';

// demoBridge mimics the SDK contract against the server's -demo card so
// the flow can be exercised without hardware.
const demoBridge = {
  name: 'demo',
  async getCertificate() {
    const r = await api('/api/demo-card/certificate');
    return { certificate: r.certificate, thumbprint: null, warning: '' };
  },
  async signDigest(digestB64, _thumbprint) {
    const r = await api('/api/demo-card/sign', { digest: digestB64 });
    return r.signature;
  },
};

// Detect the extension; fall back to the demo card if the server has it
// enabled (-demo); otherwise signing is unavailable until the bridge is
// installed.
const bridgePromise = (async () => {
  const banner = document.getElementById('bridge-banner');
  const setBanner = (text, cls) => {
    if (banner) { banner.textContent = text; banner.className = cls; }
  };

  const native = await detectBridge();
  if (native) {
    setBanner('Smart card bridge connected — signatures will use your card.', 'banner connected');
    return native;
  }

  const demoEnabled = await fetch('/api/demo-card/certificate')
    .then((r) => r.ok).catch(() => false);
  if (demoEnabled) {
    setBanner(
      'Demo mode: no bridge extension detected, using a server-held test key. ' +
      'See the project README to install the smart card bridge.', 'banner');
    return demoBridge;
  }

  setBanner(
    'No signing bridge detected — install the browser extension and native host ' +
    '(see the project README), then reload this page.', 'banner');
  return null;
})();

async function api(url, body) {
  const opts = body
    ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
    : {};
  const resp = await fetch(url, opts);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || `${resp.status} ${resp.statusText}`);
  return data;
}

async function signItem(itemId, statusEl, btn) {
  btn.disabled = true;
  const step = (msg) => { statusEl.className = 'status'; statusEl.textContent = msg; };
  try {
    const bridge = await bridgePromise;
    if (!bridge) throw new Error('no signing bridge available — install the browser extension first');
    step('Reading certificate from card…');
    const { certificate, thumbprint, warning } = await bridge.getCertificate();

    step('Preparing document on server…');
    const { token, digest } = await api('/api/sign/start', { itemId, certificate });

    step('Waiting for card to sign (PIN prompt)…');
    const signature = await bridge.signDigest(digest, thumbprint);

    step('Embedding signature…');
    await api('/api/sign/finish', { token, signature });

    // refresh() removes this card from the pending list, so the result
    // (and any certificate warning) is shown on the item's signed card.
    await refresh();
    const signedStatus = document.querySelector(
      `#signed .card[data-id="${CSS.escape(itemId)}"] .status`);
    if (signedStatus) {
      signedStatus.className = 'status ok';
      signedStatus.textContent = warning ? `Signed ✓ — note: ${warning}` : 'Signed ✓';
    }
  } catch (err) {
    statusEl.className = 'status err';
    statusEl.textContent = `Failed: ${err.message}`;
    btn.disabled = false;
  }
}

async function verifyItem(itemId, statusEl) {
  statusEl.className = 'status';
  statusEl.textContent = 'Verifying…';
  try {
    const r = await api(`/api/verify?item=${encodeURIComponent(itemId)}`);
    const s = r.signers && r.signers[0];
    if (s && s.validSignature) {
      statusEl.className = 'status ok';
      statusEl.textContent =
        `Valid signature by ${s.name || 'unknown'} — reason: ${s.reason || 'n/a'}` +
        (s.trustedIssuer ? '' : ' (issuer not trusted — demo cert)');
    } else {
      statusEl.className = 'status err';
      statusEl.textContent = `Invalid or missing signature ${r.error ? '— ' + r.error : ''}`;
    }
  } catch (err) {
    statusEl.className = 'status err';
    statusEl.textContent = `Verify failed: ${err.message}`;
  }
}

function card(name) {
  const el = document.createElement('div');
  el.className = 'card';
  const nameEl = document.createElement('span');
  nameEl.className = 'name';
  nameEl.textContent = name;
  el.appendChild(nameEl);
  return el;
}

async function refresh() {
  const { pending, signed } = await api('/api/items');

  const pendingEl = document.getElementById('pending');
  pendingEl.replaceChildren();
  if (!pending.length) {
    pendingEl.innerHTML = '<p class="empty">Nothing waiting for approval.</p>';
  }
  for (const item of pending) {
    const el = card(item.name);
    // Review shows the exact bytes that will be digested and signed.
    const review = document.createElement('a');
    review.href = `/pending/${encodeURIComponent(item.name)}`;
    review.target = '_blank';
    review.textContent = 'Review';
    const btn = document.createElement('button');
    btn.textContent = 'Approve & sign';
    const status = document.createElement('span');
    status.className = 'status';
    btn.onclick = () => signItem(item.id, status, btn);
    el.append(review, btn, status);
    pendingEl.appendChild(el);
  }

  const signedEl = document.getElementById('signed');
  signedEl.replaceChildren();
  if (!signed.length) {
    signedEl.innerHTML = '<p class="empty">No signed documents yet.</p>';
  }
  for (const item of signed) {
    const el = card(item.name);
    el.dataset.id = item.id;
    const link = document.createElement('a');
    link.href = item.url;
    link.textContent = 'Download';
    const btn = document.createElement('button');
    btn.className = 'secondary';
    btn.textContent = 'Verify';
    const status = document.createElement('span');
    status.className = 'status';
    btn.onclick = () => verifyItem(item.id, status);
    el.append(link, btn, status);
    signedEl.appendChild(el);
  }
}

refresh().catch((err) => {
  document.getElementById('pending').innerHTML =
    `<p class="status err">Failed to load items: ${err.message}</p>`;
});
