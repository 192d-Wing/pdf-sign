# Security scanning: triage and suppressions

The DevSecOps pipeline (`.github/workflows/devsecops.yml`) runs CodeQL,
gosec, Semgrep, govulncheck, OSV-Scanner, Trivy (fs/config/image), Checkov,
and Grype. This document records how findings are triaged and why specific
alerts are suppressed, for auditors and future maintainers.

Rule: **fix by default; suppress only what is a false positive or a
deployment-time/by-design deviation, and always with a reason.**

## Fixed in code / manifests

| Finding(s) | Resolution |
|---|---|
| Dockerfile no USER / no HEALTHCHECK (Trivy DS-0002, Semgrep missing-user, CKV_DOCKER_2/3) | Explicit `USER 65532:65532` and a `HEALTHCHECK` using the binary's `-healthcheck` TCP dial (image is distroless — no shell/curl). |
| Pod/container hardening (Trivy KSV-0011/0020/0021/0110, CKV_K8S_11/15/21/38/40, CKV2_K8S_6) | `runAsUser/runAsGroup: 65532`, `automountServiceAccountToken: false`, CPU limit, `imagePullPolicy: Always`, base namespace, and a `NetworkPolicy` (ingress to the service port; egress to DNS + TLS). |
| TLS MinVersion not set (Semgrep missing-ssl-minversion) | `MinVersion: tls.VersionTLS12` on both servers' `tls.Config`. |
| postMessage origin not validated (Semgrep) | Added `event.origin === window.location.origin` checks in `pdfsign-client.js` and the extension `content.js` (on top of the existing `source === window` check). |
| Log injection (CodeQL go/log-injection) | `signing.SanitizeLogField` strips control characters from certificate CNs and item IDs before logging (commit that added it). |

## Suppressed — false positives

| ID | Location | Why |
|---|---|---|
| CodeQL `go/log-injection` | `cmd/pdf-sign/handlers.go` | The flagged log calls are already routed through `signing.SanitizeLogField`, which removes CR/LF. CodeQL's default taint model doesn't recognize the custom sanitizer. Dismissed via the code-scanning API with reason "false positive". |
| Semgrep `use-of-sha1` | `bridge/host/winsign.go` | SHA-1 computes the Windows certificate *thumbprint* — an identifier used to locate the cert in the store, never for signing or integrity. Suppressed inline with `nosemgrep: use-of-sha1` and dismissed via API. |

## Suppressed — by-design / deployment-time

Configured in `.trivyignore` and inline `# checkov:skip=` comments:

| ID | Why |
|---|---|
| Trivy AVD-KSV-0013 / Checkov CKV_K8S_43 (image digest) | Manifests ship with a tag so `kubectl apply -k` / `helm install` are runnable; the image is pinned by digest at deploy time (`kustomize images.digest`, `values.image.digest`, or the CD pipeline). |
| Trivy AVD-KSV-0125 (trusted registries) | Registry allow-listing is enforced by a cluster admission controller (Kyverno/Gatekeeper), not a Deployment field. |
| Checkov CKV_K8S_21 (default namespace) on Helm templates | Helm installs into the release namespace (`helm install -n`); chart templates intentionally omit a hardcoded namespace. The Kustomize base sets `namespace: pdfsign`. |
| Trivy license findings (BSD-2/3-Clause, MIT) | License *detections*, not vulnerabilities. All dependencies are permissive and compatible. |

## Accepted risk (documented, not suppressed)

- **CPU limits**: a CPU *limit* is now set to satisfy scanners, but note that
  omitting CPU limits (request-only) is also a defensible pattern to avoid
  throttling. Adjust `resources.limits.cpu` to your cluster's policy.

## How to re-triage

- Add a finding to the tables above before suppressing it.
- Prefer inline suppression (`nosemgrep:`, `# checkov:skip=`,
  `# trivy:ignore:`) over blanket config so the reason lives next to the code.
- API-dismissed alerts (CodeQL) are recorded in the repo's code-scanning
  alert history with the dismissal reason.
