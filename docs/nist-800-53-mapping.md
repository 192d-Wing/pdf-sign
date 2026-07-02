# NIST SP 800-53 Rev 5 control mapping

Control-to-implementation matrix for ATO/RMF artifacts (SSP control
implementation statements). Each control listed here is also annotated at
the enforcing code with a `NIST 800-53r5` comment — grep the codebase for
`800-53r5` to regenerate the evidence list.

Scope: the pdf-sign application stack (signing engine, demo approval app,
signing API service, workstation bridge). Platform controls (OS, cluster,
network, physical) are inherited from the hosting environment and are
noted in the last section.

## Implemented in code

| Control | Name | Implementation | Evidence (code) |
|---|---|---|---|
| AC-3 | Access Enforcement | Sessions are owner/tenant-scoped — only the creating identity can complete or cancel a signature. Extension relays card access only for allowlisted web origins; browser enforces the host-manifest extension allowlist. | `internal/signing/signing.go` (`takeOwned`), `bridge/extension/background.js`, `bridge/extension/manifest.json`, `bridge/host/main.go` |
| AC-6 | Least Privilege | With mTLS login, a user may only sign with a certificate whose subject CN matches their authenticated identity. Containers run nonroot, read-only rootfs, all capabilities dropped. | `cmd/pdf-sign/handlers.go` (`authorizeSigningCert`), `deploy/helm/pdfsign-svc/templates/deployment.yaml`, `deploy/kustomize/base/deployment.yaml` |
| AC-12 | Session Termination | Abandoned signing sessions are cancelled automatically at the 5-minute TTL; the parked cryptographic operation is unwound and in-memory document copies released. | `internal/signing/signing.go` (`NewManager`, `janitor`) |
| AU-2 / AU-3 / AU-12 | Audit Events / Content / Generation | Every signature lifecycle event (session create, complete) is logged with tenant, signer CN, session ID, and timestamp. | `cmd/pdfsign-svc/main.go` (`handleCreate`, `handleComplete`), `cmd/pdf-sign/handlers.go` (`handleSignStart`, `handleSignFinish`) |
| AU-10 | Non-repudiation | PAdES digital signatures bind documents to the signer's PKI identity. The bridge prefers the card's non-repudiation (ContentCommitment) certificate; with mTLS login the signature identity must match the session identity. | `internal/signing/` (package), `bridge/host/winsign.go` (cert ranking), `cmd/pdf-sign/handlers.go` |
| CM-7 | Least Functionality | Demo signing oracle exists only behind `-demo`; dev bearer auth only behind `-dev` and mutually exclusive with tenant mTLS. Native host opens no network listeners and exits after one request. Distroless container (no shell). | `cmd/pdf-sign/main.go`, `cmd/pdfsign-svc/main.go`, `bridge/host/main.go`, `deploy/docker/Dockerfile` |
| IA-2(1)/(2) | Multi-factor Authentication | Each signature requires the smart card (possession) plus PIN (knowledge), enforced by the card via Windows CNG. | `bridge/host/winsign.go` (`signDigest`) |
| IA-2(12) | Acceptance of PIV Credentials | Optional mTLS login mode authenticates users with their PIV/CAC TLS client certificate against DoD CAs. | `cmd/pdf-sign/main.go` (TLS config) |
| IA-5(2) | PKI-based Authentication | Certification-path validation of signing certificates to organization trust anchors (`-sign-ca`) before any signing; tenant client certs validated to `-client-ca` in the TLS handshake; credential-expiry warnings surfaced to users. | `internal/signing/signing.go` (`ValidateCert`), `cmd/pdfsign-svc/main.go` (`tenant`), `bridge/host/winsign.go` (`certWarning`) |
| IA-9 | Service Identification and Authentication | Integrating backends (tenants) authenticate to the signing service with PKI client certificates over mutual TLS; tenant identity = certificate CN. | `cmd/pdfsign-svc/main.go` (`tenant`, TLS config) |
| SC-5 / SC-5(2) | Denial-of-service Protection | Request body caps, strict content types, HTTP read/write/idle timeouts, and per-tenant concurrent-session quotas. | `cmd/*/main.go` (server timeouts), `decodeJSON` in both handlers, `internal/signing/signing.go` (`maxPerOwner`) |
| SC-8 / SC-8(1) | Transmission Confidentiality and Integrity | TLS 1.2+ (Go crypto/tls defaults) for all server traffic in production modes; deployment manifests use TLS passthrough so encryption terminates only inside the pod. | `cmd/*/main.go`, `deploy/` (passthrough ingress) |
| SC-12 | Cryptographic Key Establishment and Management | Signing private keys are generated and held on the smart card and never leave it; the host process holds only a CNG key handle. Server TLS keys are mounted from Kubernetes Secrets. | `bridge/host/winsign.go`, `deploy/` |
| SC-13 | Cryptographic Protection | SHA-256 digests; RSA PKCS#1 v1.5 / ECDSA signatures produced by the card and verified with Go stdlib crypto; TLS via crypto/tls. | `internal/signing/signing.go`, `bridge/host/winsign.go` |
| SC-17 | PKI Certificates | Trust anchors are organization-approved CA bundles supplied as configuration (`-sign-ca`, `-client-ca`), not hardcoded. | `internal/signing/signing.go` (`LoadCertPool`), flag wiring in both `main.go` |
| SC-18 | Mobile Code | Content-Security-Policy restricts the signing page to same-origin scripts; injected inline code does not execute. | `cmd/pdf-sign/main.go` (`securityHeaders`) |
| SC-23 / SC-23(3) | Session Authenticity / Unique Session Identifiers | TLS session authenticity; signing-session tokens are 128-bit crypto/rand values, single-use, and expire at TTL. | `internal/signing/signing.go` (`newToken`, `takeOwned`) |
| SC-24 | Fail in Known State | Both binaries refuse to start in an unsafe configuration (production without cert validation; dev auth combined with tenant auth) rather than degrading at runtime. | `cmd/pdf-sign/main.go`, `cmd/pdfsign-svc/main.go` |
| SI-7 | Software, Firmware, and Information Integrity | Client-supplied signatures are cryptographically verified against the submitted certificate before being embedded; outputs are written via temp-file + atomic rename so failures never corrupt published documents. | `internal/signing/signing.go` (`verifyRawSignature`), `cmd/pdf-sign/handlers.go` (`publishSigned`) |
| SI-10 | Information Input Validation | Strict content types, bounded bodies, base64/DER parsing with rejection, item-ID path-traversal checks, digest length checks. | `decodeJSON` (both), `cmd/pdf-sign/items.go` (`validItemID`), `bridge/host/winsign.go` |

## Inherited from the platform / environment

| Control family | Inherited from |
|---|---|
| AC-2 (account management) | Directory/IdP of the integrating site; PKI registration (CAC issuance) |
| AU-4, AU-9, AU-11 (audit storage, protection, retention) | Log aggregation the stderr stream is shipped to |
| CP, PE, MP families | Hosting environment / data center |
| SC-7 (boundary protection) | Cluster network policy, firewalls; the native host contributes by opening no listeners |
| SC-28 (protection at rest) | Documents transit memory only in the service (session TTL); the demo app's `data/` directory inherits filesystem/disk encryption from the host |
| IA-5(13) etc. (credential lifecycle) | Issuing PKI (e.g., DoD PKI) |

## Known gaps (POA&M candidates)

- **AU-10 long-term validation**: no RFC 3161 trusted timestamp yet —
  signatures are verifiable only while the signer's certificate chain is
  valid. Planned: `SignData.TSA.URL` in `internal/signing`.
- **SC-13 FIPS validation**: Go's standard crypto is not FIPS 140-3
  validated by default; if the ATO requires a validated module, build with
  the Go FIPS-140 mode (GODEBUG=fips140=on / BoringCrypto toolchain) and
  document the module. Card-side signing already uses the card's validated
  module via CNG.
- **AU-9 in the demo app**: audit records go to stderr; protection and
  retention require the deployment to ship them to controlled storage.
- **IA-5(2) revocation**: signing-cert chain validation does not yet check
  OCSP/CRL at signing time (verification-time revocation data exists in
  the verify endpoint). Planned alongside LTV support.
