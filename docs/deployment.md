# Deployment guide

How to roll out the pdf-sign stack: one server-side component (the demo
approval app **or** the signing service) plus two workstation-side
components (the browser extension and the native host). Written for a
Windows/AD environment with PIV/CAC cards; adjust paths for anything else.

Companion docs: [README](../README.md) (architecture, flags),
[client_design.md](client_design.md) (bridge protocol and security model).

## What gets deployed where

| Component | Deploy to | Artifact |
|---|---|---|
| `pdf-sign` (approval app) or `pdfsign-svc` (API service) | One server | Single static Go binary |
| Browser extension | Every workstation, per browser | Force-installed extension |
| `pdfsign-bridge.exe` + host manifest + registry keys | Every workstation | Signed exe + JSON + 2 registry values |
| CA bundles (`sign-ca`, `client-ca`) | Server | PEM files |

Nothing on the workstation listens on a port; nothing on the server needs
card hardware.

## 1. Build release artifacts

On any machine with Go (binaries are static, no runtime dependencies):

```powershell
$v = "0.1.0"
go build -trimpath -ldflags "-s -w" -o dist\pdf-sign.exe        .\cmd\pdf-sign
go build -trimpath -ldflags "-s -w" -o dist\pdfsign-svc.exe     .\cmd\pdfsign-svc
go build -trimpath -ldflags "-s -w" -o dist\pdfsign-bridge.exe  .\bridge\host
```

For a Linux server host: `$env:GOOS='linux'; $env:GOARCH='amd64'` before the
server builds (the bridge is Windows-only by design).

**Code-sign `pdfsign-bridge.exe`** with your organization's Authenticode
certificate. Unsigned binaries pushed by GPO will trip SmartScreen/AppLocker
on managed endpoints.

## 2. PKI prerequisites

Collect these PEM bundles before configuring anything:

- **`sign-ca.pem`** — the CAs that end-user *signing* certificates chain to.
  For DoD CACs, download the DoD PKI CA bundle from DISA (cyber.mil → "PKI/PKE
  Document Library" → "PKI CA Certificate Bundles: PKCS#7") and convert, or
  export from a domain machine:
  ```powershell
  $ca = Get-ChildItem Cert:\LocalMachine\CA | Where-Object Subject -like '*DOD*CA*'
  $pem = $ca | ForEach-Object {
    "-----BEGIN CERTIFICATE-----`n" +
    [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks') +
    "`n-----END CERTIFICATE-----" }
  ($pem -join "`n") | Set-Content sign-ca.pem
  ```
  Include intermediates (the issuing CAs), not just roots — the browser
  bridge sends only the leaf certificate.
- **Server TLS certificate** — from your internal CA, SAN matching the
  server's DNS name.
- **`client-ca.pem`** (only for `pdfsign-svc`, or CAC-login mode of the
  demo app) — the CA(s) that issue TLS *client* certificates:
  - For `pdfsign-svc` tenants: your internal CA that issues service
    certificates to integrating backends. Tenant identity = client cert CN.
  - For CAC login on the demo app: the same DoD bundle as `sign-ca.pem`.

## 3. Server deployment

### Option A — demo approval app (`pdf-sign.exe`)

```powershell
pdf-sign.exe -addr 0.0.0.0:8443 `
  -sign-ca C:\pdfsign\sign-ca.pem `
  -tls-cert C:\pdfsign\server.crt -tls-key C:\pdfsign\server.key `
  -client-ca C:\pdfsign\sign-ca.pem      # optional: CAC mTLS login
```

- Never pass `-demo` outside development; the binary refuses to start
  without either `-demo` or `-sign-ca`, so a misconfigured production start
  fails loudly.
- `data\pending`, `data\signed`, `data\archive` are created relative to the
  working directory — set the service's working directory to a data drive
  and back it up.

### Option B — signing service (`pdfsign-svc.exe`)

```powershell
pdfsign-svc.exe -addr 0.0.0.0:8443 `
  -sign-ca C:\pdfsign\sign-ca.pem `
  -tls-cert C:\pdfsign\server.crt -tls-key C:\pdfsign\server.key `
  -client-ca C:\pdfsign\client-ca.pem `
  -max-sessions 32
```

- Issue each integrating website's backend a client certificate from the
  `client-ca`. Revoking a tenant = revoking (or just not renewing) its cert.
- `-dev` (bearer token, plain HTTP) is for local development only and
  refuses to combine with `-client-ca`. There is no bearer path in
  production mode — callers without a client certificate fail the TLS
  handshake.
- The service holds PDFs in memory for the 5-minute session TTL only;
  size instances accordingly (`-max-sessions` × tenant count × typical PDF
  size bounds worst-case memory).

### Run as a Windows service

```powershell
New-Service -Name pdfsign -BinaryPathName `
  '"C:\pdfsign\pdfsign-svc.exe" -addr 0.0.0.0:8443 -sign-ca C:\pdfsign\sign-ca.pem -tls-cert C:\pdfsign\server.crt -tls-key C:\pdfsign\server.key -client-ca C:\pdfsign\client-ca.pem' `
  -DisplayName "pdf-sign signing service" -StartupType Automatic
Start-Service pdfsign
```

(Plain Go binaries run fine under the service control manager for
auto-restart; use NSSM or a wrapper if you want stdout log capture, or
redirect logs via Task Scheduler instead.) On Linux, use a systemd unit
with `Restart=on-failure`.

### Kubernetes / k3s

Container image, Helm chart, and Kustomize overlays for `pdfsign-svc` live
in [`deploy/`](../deploy/README.md) — including the TLS-passthrough ingress
configurations (ingress-nginx for standard clusters, Traefik
`IngressRouteTCP` for k3s) that the next section explains the need for.

### Reverse proxies — caution with mTLS

If you must front the service with a proxy/load balancer, it needs to
**pass through TLS** (TCP/SNI passthrough) — terminating TLS at the proxy
breaks client-certificate authentication unless the proxy re-injects the
cert and the service is changed to trust a header. Simplest correct setup:
expose the Go binary directly; it already has timeouts and TLS configured.
Sessions are in-memory, so multiple instances need sticky routing.

### Firewall

Open the one listener port (e.g. 8443/tcp) to the callers that need it:
user workstations for the approval app; integrating backends only (not
users) for `pdfsign-svc`.

## 4. Workstation deployment

Two artifacts per workstation. Both are user-context; no admin rights are
needed at install time if you deploy per-user, or deploy machine-wide with
HKLM as below.

### 4a. Browser extension

1. Package `bridge/extension` and publish it — Chrome Web Store /
   Edge Add-ons (can be unlisted), or self-host the CRX for
   Edge/Chrome enterprise policies.
2. Force-install via policy (GPO/Intune → Chrome and Edge ADMX):
   - Chrome: `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist`
   - Edge: `HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist`
   - Value format: `<extension-id>;<update-url>`
3. Before publishing, set the production origins in
   `manifest.json → content_scripts.matches` **and**
   `background.js → ALLOWED_ORIGINS` (they must stay in sync), e.g.
   `https://approvals.example.org/*`.

The published extension ID is stable — record it; the native host manifest
needs it.

### 4b. Native host

Files (push with GPO file preferences / Intune Win32 app):

```
C:\Program Files\pdf-sign-bridge\pdfsign-bridge.exe        (code-signed)
C:\Program Files\pdf-sign-bridge\com.pdfsign.bridge.json
```

`com.pdfsign.bridge.json` (must be UTF-8 **without BOM** — Chrome rejects a
BOM; don't generate it with `Set-Content -Encoding UTF8` under Windows
PowerShell 5.1):

```json
{
  "name": "com.pdfsign.bridge",
  "description": "pdf-sign smart card bridge",
  "path": "C:\\Program Files\\pdf-sign-bridge\\pdfsign-bridge.exe",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://<PRODUCTION-EXTENSION-ID>/"]
}
```

Registry (machine-wide; HKCU works too for per-user installs):

```
HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.pdfsign.bridge
    (Default) = C:\Program Files\pdf-sign-bridge\com.pdfsign.bridge.json
HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\com.pdfsign.bridge
    (Default) = C:\Program Files\pdf-sign-bridge\com.pdfsign.bridge.json
```

`bridge/host/install.ps1` does the per-user (HKCU) equivalent of all of
this for development machines.

## 5. Smoke tests

Workstation (no PIN needed):

```powershell
& 'C:\Program Files\pdf-sign-bridge\pdfsign-bridge.exe' -cli ping
& 'C:\Program Files\pdf-sign-bridge\pdfsign-bridge.exe' -cli list   # should list card certs
```

Browser: open the approval page — banner must read "Smart card bridge
connected". If it doesn't, inspect the extension's service worker console
(`chrome://extensions` → Inspect views); `Specified native messaging host
not found` means the registry value or manifest (BOM!) is wrong.

Server (`pdfsign-svc`): from an integrating backend's host, with its client
cert:

```
curl --cert tenant.crt --key tenant.key --cacert internal-ca.pem \
  https://sign.example.org:8443/v1/signing-sessions -X POST \
  -H "Content-Type: application/json" -d '{}'      # expect 400 (auth passed, bad body)
```

A `tls: certificate required` error instead means the client cert wasn't
presented or doesn't chain to `-client-ca` — that's the auth layer working.

End-to-end: sign one real document per pilot workstation and check the
result in Adobe Reader (signature panel shows the signer and, once the DoD
chain is trusted on the machine, a green check).

## 6. Operations

- **Logs**: both binaries log one line per session create/complete to
  stderr, including tenant and signer CN — capture and retain them; they
  are your signing audit trail (pair with the archived source documents in
  the approval app's `data\archive`).
- **Certificate expiry**: the bridge warns users 14 days before their
  signing cert expires. Monitor your server TLS cert and tenant client
  certs separately.
- **Upgrades**: server binaries are drop-in replacements (sessions are
  in-flight state only; drain for 5 minutes or accept killing pending
  sessions — pending items stay pending and users just retry). Bridge
  upgrades: replace the exe; the extension updates through the store
  channel. Protocol changes must keep `pdfsign-client.js`, the extension,
  and the host in step — version all three together.
- **Known limitation**: no RFC 3161 timestamping yet — signatures validate
  only while the signer's cert chain is valid. Configure a TSA
  (`SignData.TSA.URL` in `internal/signing`) before relying on long-term
  validation.

## 7. Rollout checklist

- [ ] `sign-ca.pem` assembled (roots **and** intermediates) and tested
      against a real user certificate
- [ ] Server TLS cert issued; service runs and restarts on boot
- [ ] `pdfsign-svc` only: tenant client certs issued; each integrator
      tested with the smoke curl
- [ ] Extension published with production origins; ID recorded
- [ ] Extension force-install policy applied to a pilot OU
- [ ] `pdfsign-bridge.exe` code-signed; files + registry pushed to pilot OU
- [ ] Pilot workstation: `-cli list` shows certs, banner green, one real
      document signed and verified in Adobe Reader
- [ ] Logs collected centrally; alert on service down
- [ ] Demo/dev modes (`-demo`, `-dev`) absent from all production command
      lines (both binaries refuse unsafe defaults, but check anyway)
