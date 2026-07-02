# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-02

First release.

### Added

- Deferred remote-hash PAdES signing engine — the document hash is signed
  remotely without the private key leaving the smart card.
- `pdfsign-svc`: multi-tenant deferred-signing HTTP API (mutual TLS in
  production; `-dev` bearer-token mode for local development).
- `pdf-sign`: desktop approval web app and browser SDK.
- Browser extension and Windows CNG native-messaging host (`pdfsign-bridge`)
  for smart-card signing.
- RFC 3161 trusted timestamps and a FIPS 140-3 build mode.
- Deployment assets: distroless Dockerfile, Helm chart, and Kustomize overlays.
- Architecture, client-design, and deployment documentation, annotated with
  NIST 800-53r5 controls for ATO artifacts.

### Security

- Hardened TSA transport, added per-tenant session quotas, and tightened
  request logging.

### CI/CD

- CI across Windows/Linux × amd64/arm64 (build, test, `go vet`, `gofmt`,
  govulncheck).
- Release pipeline: signed multi-arch binaries and a signed `pdfsign-svc`
  container image (Cosign keyless signature, SBOM, and SLSA provenance).
- DevSecOps pipeline: CodeQL (Go + JavaScript/TypeScript), gosec, Semgrep,
  Trivy (fs/config/image), Grype, OSV-Scanner, Gitleaks, Checkov, and OWASP
  ZAP DAST — findings centralized in GitHub code scanning.
- All GitHub Actions pinned to commit SHAs; Dependabot enabled for Go modules,
  Actions, and the container base image.

[Unreleased]: https://github.com/192d-Wing/pdf-sign/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/192d-Wing/pdf-sign/releases/tag/v0.1.0
