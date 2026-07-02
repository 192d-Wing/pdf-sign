# Deploying pdfsign-svc to Kubernetes / k3s

Manifests for the signing **service** (`cmd/pdfsign-svc`) — the component
other websites' backends call. The demo approval app and the workstation
bridge are not containerized here (the bridge runs on user workstations by
design; see [docs/deployment.md](../docs/deployment.md)).

```
deploy/
├── docker/Dockerfile          # multi-stage build → distroless, nonroot
├── helm/pdfsign-svc/          # Helm chart (k8s and k3s via values)
└── kustomize/
    ├── base/                  # Deployment + Service (ClusterIP)
    └── overlays/
        ├── k8s/               # + ingress-nginx Ingress (SSL passthrough)
        └── k3s/               # + Traefik IngressRouteTCP (TLS passthrough)
```

## The one rule that shapes everything: TLS passthrough

The pod terminates TLS itself and **requires client certificates** (that
is the tenant authentication). Any ingress or load balancer in front of it
must pass TLS through untouched:

- ingress-nginx: `nginx.ingress.kubernetes.io/ssl-passthrough` (controller
  must run with `--enable-ssl-passthrough`)
- Traefik (k3s default): `IngressRouteTCP` with `tls.passthrough: true`
- Cloud LBs: use L4/TCP mode, never L7/HTTPS

If the edge terminates TLS, every request arrives without a client cert
and authentication breaks — fail-closed, but broken.

## 1. Build and push the image

```sh
docker build -f deploy/docker/Dockerfile -t registry.example.org/pdfsign-svc:0.1.0 .
docker push registry.example.org/pdfsign-svc:0.1.0
```

## 1a. Pin the image by digest

Deployments reference the image by immutable digest (scanners require it;
`:tag` is mutable). Grab the digest after pushing:

```sh
docker buildx imagetools inspect registry.example.org/pdfsign-svc:0.1.0 \
  --format '{{.Manifest.Digest}}'
```

Put it in **one file** for whichever tool you use:

- **Kustomize** — [`kustomize/image/kustomization.yaml`](kustomize/image/kustomization.yaml)
  (`newName` + `digest`). Both overlays consume it; the base keeps a plain
  tag for local `kubectl kustomize` inspection.
- **Helm** — [`helm/pdfsign-svc/values-image.example.yaml`](helm/pdfsign-svc/values-image.example.yaml)
  (`image.repository` + `image.digest`); pass it with `-f`.

## 2. Create the secrets

```sh
kubectl create namespace pdfsign
kubectl -n pdfsign create secret tls pdfsign-tls \
  --cert=server.crt --key=server.key
kubectl -n pdfsign create secret generic pdfsign-cas \
  --from-file=sign-ca.pem --from-file=client-ca.pem
```

`sign-ca.pem`: CAs the end-user signing certs chain to (include
intermediates). `client-ca.pem`: the CA issuing tenant client certs.
See [docs/deployment.md](../docs/deployment.md) §2.

## 3a. Install with Helm

```sh
helm install pdfsign deploy/helm/pdfsign-svc -n pdfsign \
  --set image.repository=registry.example.org/pdfsign-svc \
  --set ingress.enabled=true --set ingress.host=sign.example.org        # k8s + ingress-nginx
# or, on k3s:
helm install pdfsign deploy/helm/pdfsign-svc -n pdfsign \
  --set image.repository=registry.example.org/pdfsign-svc \
  --set traefik.ingressRouteTCP.enabled=true \
  --set traefik.ingressRouteTCP.host=sign.example.org
```

Local development on k3s (bearer token, plain HTTP — never production):

```sh
helm install pdfsign deploy/helm/pdfsign-svc -n pdfsign --set dev.enabled=true
kubectl -n pdfsign logs deploy/pdfsign -f | grep "bearer token"
```

## 3b. Or apply with Kustomize

Edit the image in `kustomize/base/kustomization.yaml` and the host in the
overlay, then:

```sh
kubectl apply -k deploy/kustomize/overlays/k8s    # standard cluster, ingress-nginx
kubectl apply -k deploy/kustomize/overlays/k3s    # k3s, bundled Traefik
```

## 4. Smoke test

From an integrating backend's host (expect **400** — auth passed, empty
body rejected; `tls: certificate required` means the client cert is
missing or wrong):

```sh
curl --cert tenant.crt --key tenant.key --cacert internal-ca.pem \
  https://sign.example.org/v1/signing-sessions \
  -X POST -H "Content-Type: application/json" -d '{}'
```

## Scaling note

Signing sessions live in pod memory: `replicas: 1` is the default. To
scale out you need TCP-level session affinity (e.g. source-IP sticky at
the L4 LB) or an external session store — see the "State & scale" item in
the production checklist.
