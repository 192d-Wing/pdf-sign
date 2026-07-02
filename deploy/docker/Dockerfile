# Build from the repo root:
#   docker build -f deploy/docker/Dockerfile -t registry.example.org/pdfsign-svc:0.1.0 .
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
# NIST 800-53r5 SC-13: build against the Go FIPS 140-3 Cryptographic
# Module (frozen, validated version). The binary logs "FIPS 140-3 mode:
# true" at startup as evidence.
ARG GOFIPS140=v1.0.0
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOFIPS140=$GOFIPS140 \
    go build -trimpath -ldflags="-s -w" -o /out/pdfsign-svc ./cmd/pdfsign-svc

# Distroless static: no shell, no package manager, runs as nonroot (65532).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pdfsign-svc /pdfsign-svc
# Run as the nonroot UID:GID explicitly (defense in depth; the base image
# already defaults to this, but stating it satisfies image scanners and
# survives a base-image change).
USER 65532:65532
EXPOSE 8443
# The service requires TLS client certificates, so an HTTP health probe
# cannot complete the handshake. A TCP dial to the listener is the
# meaningful liveness signal; the binary has no shell, so we use its own
# built-in check. Orchestrators should prefer a tcpSocket probe (see the
# K8s manifests); this HEALTHCHECK covers plain `docker run`.
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["/pdfsign-svc", "-healthcheck", "127.0.0.1:8443"]
ENTRYPOINT ["/pdfsign-svc"]
