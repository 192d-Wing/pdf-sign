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
EXPOSE 8443
ENTRYPOINT ["/pdfsign-svc"]
