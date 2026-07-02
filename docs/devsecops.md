# DevSecOps & Certificate-to-Field (CtF) evidence

This repo's CI/CD is structured to produce the security artifacts an Authorizing
Official (AO) expects for a DoD **Certificate to Field (CtF)** / RMF **Authority
to Operate (ATO)** decision. The automated gates cover the *technical* controls;
the rows marked **Manual** still need a human-authored artifact in the body of
evidence (BoE).

## Pipelines

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | push / PR | Build + unit test on Linux/Windows/macOS, `gofmt`, `go vet`, `govulncheck`. |
| `devsecops.yml` | push / PR / **weekly cron** / manual | SAST, SCA, secrets, IaC, container scan + SBOM, DAST. |
| `release.yml` | tag `v*` | Signed multi-arch binaries + **signed, attested** container image. |
| `dependabot.yml` | schedule | Continuous dependency & base-image patching. |

The weekly `schedule:` on `devsecops.yml` is the **RMF Continuous Monitoring
(ConMon)** driver — it re-scans released code against newly disclosed CVEs even
when nothing changed.

## Gate → control mapping

| Gate | Tooling | NIST 800-53 (Rev 5) | DoD reference |
|---|---|---|---|
| SAST | CodeQL, gosec, Semgrep | SA-11(1), RA-5 | DoD Enterprise DevSecOps — *Static Analysis* |
| SCA (deps) | govulncheck, OSV-Scanner, Trivy fs | RA-5, SA-11, SR-3 | *Software Composition Analysis* |
| License compliance | go-licenses | SA-4, SR-11 | Open-source IP review |
| Secrets | Gitleaks | IA-5, SC-12/28 | Credential hygiene |
| IaC / config | Trivy config, Checkov | CM-6, CM-7, SA-15 | Hardening / STIG |
| Container vuln | Trivy image, Grype | RA-5, SI-2, SI-3 | Container Hardening Guide |
| SBOM | Syft (SPDX + CycloneDX) | SR-4, SA-8 | **EO 14028** SBOM requirement |
| Image signing | Cosign (keyless) + SLSA provenance | SR-4(3), SI-7, CM-14 | Supply-chain integrity |
| DAST | OWASP ZAP baseline | CA-8, SA-11(8), SI-10 | Dynamic testing |
| ConMon | scheduled re-scan | CA-7, RA-5(2) | Continuous Monitoring |

## Where findings go

- **SARIF → GitHub code scanning** (the "single pane"): CodeQL, gosec, Semgrep,
  Trivy (fs/config/image), Grype, Checkov. Requires **GitHub Advanced Security**
  (free on public repos; a license on private repos). Export this view as CVE
  evidence / POA&M input.
- **Artifacts**: SBOM (`sbom-pdfsign-svc`), license inventory (`license-inventory`).
- **Registry attestations**: the released image carries a cosign signature, an
  SPDX SBOM attestation, and a `mode=max` SLSA provenance attestation. Verify:

  ```
  cosign verify ghcr.io/192d-wing/pdfsign-svc:<tag> \
    --certificate-identity-regexp 'https://github.com/192d-wing/pdf-sign/.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  cosign verify-attestation --type spdxjson ghcr.io/192d-wing/pdfsign-svc:<tag> ...
  ```

## Tuning the gates (do this before go-live)

1. **Trivy image scan fails on Critical/High** (`exit-code: "1"`, `ignore-unfixed:
   true`). Track accepted risks in `.trivyignore` with a POA&M reference, not by
   loosening the gate.
2. **ZAP baseline** currently runs passive (`-I`, `fail_action: false`). Once the
   alert set is triaged, commit `.zap/rules.tsv`, drop `-I`, and set
   `fail_action: true`. For real API coverage, feed ZAP an OpenAPI spec of the
   `/v1/signing-sessions` endpoints (import via `-z`), since baseline spidering
   won't discover POST-only routes on its own.
3. **Semgrep / Checkov** run `soft_fail` / `continue-on-error` so first adoption
   isn't blocked. Flip to blocking once the backlog is triaged.

## Gaps still needing manual artifacts (not automatable here)

- **Hardened base image / STIG.** The service uses `distroless/static` (no shell,
  nonroot 65532) which is a strong start, but a formal CtF typically wants an
  **Iron Bank (Platform One)** hardened base or an OpenSCAP/STIG scan result.
  Swap the `FROM` in `deploy/docker/Dockerfile` for the Iron Bank equivalent and
  attach the STIG checklist (`.ckl`).
- **RMF package**: SSP, SAR, POA&M, hardware/software list — **Manual**.
- **Interconnection / boundary** (mTLS is enforced in prod mode; document the
  crypto in the SSP, FIPS 140-3 validation of the signing path) — **Manual**.
- **Penetration test** (independent, beyond automated DAST) — **Manual**.
- **Crypto validation**: the Windows CNG smart-card path and PDF signing must be
  mapped to FIPS-validated modules — **Manual**.

> The pinned `github.com/digitorus/pdf v0.1.2` (held back from v0.2.0, see
> `go.mod`) is tracked as a deliberate configuration decision — Dependabot is
> configured to ignore that bump so it doesn't reopen a known-breaking PR.
