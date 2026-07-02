// pdf-sign: web-based PDF approval + smart-card signing demo app.
//
// This is the reference integrator for the reusable pieces of this repo:
// the deferred-signing engine (internal/signing), the browser SDK
// (web/pdfsign-client.js), and the workstation bridge (bridge/). Another
// website would implement the equivalent of handlers.go against either
// the signing package (Go) or the standalone API service (cmd/pdfsign-svc).
//
// Modes:
//   - Development:  go run ./cmd/pdf-sign -demo
//     Enables a "demo card" (software test key held by the server) so the
//     whole flow works without hardware. Never use in production: the
//     demo endpoints are a signing oracle.
//   - Production:   go run ./cmd/pdf-sign -sign-ca roots.pem [-tls-cert c -tls-key k [-client-ca ca.pem]]
package main

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/192d-wing/pdf-sign/internal/signing"
)

//go:embed all:web
var webFS embed.FS

const (
	pendingDir = "data/pending"
	signedDir  = "data/signed"
	archiveDir = "data/archive"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	demo := flag.Bool("demo", false, "enable the demo card (server-held TEST key); development only")
	signCA := flag.String("sign-ca", "", "PEM file of CA certificates that signing certs must chain to")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
	tlsKey := flag.String("tls-key", "", "TLS private key file")
	clientCA := flag.String("client-ca", "", "PEM file of CAs for required TLS client certificates (mTLS); needs -tls-cert/-tls-key")
	flag.Parse()

	if !*demo && *signCA == "" {
		log.Fatal("refusing to start: pass -sign-ca <roots.pem> to validate signing certificates, or -demo for development mode")
	}
	if *clientCA != "" && (*tlsCert == "" || *tlsKey == "") {
		log.Fatal("-client-ca requires -tls-cert and -tls-key")
	}

	for _, dir := range []string{pendingDir, signedDir, archiveDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("create %s: %v", dir, err)
		}
	}
	if err := ensureSamplePDFs(pendingDir); err != nil {
		log.Fatalf("generate sample PDFs: %v", err)
	}

	srv := &server{
		locks: newItemLocks(),
		demo:  *demo,
		mtls:  *clientCA != "",
	}
	// Sessions are owned by the item ID; when one expires, free the item
	// so it can be signed again.
	srv.signer = signing.NewManager(5*time.Minute, 0, func(_, itemID string) {
		srv.locks.release(itemID)
	})
	if *signCA != "" {
		pool, err := signing.LoadCertPool(*signCA)
		if err != nil {
			log.Fatalf("load -sign-ca: %v", err)
		}
		srv.signRoots = pool
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/items", srv.handleItems)
	mux.HandleFunc("POST /api/sign/start", srv.handleSignStart)
	mux.HandleFunc("POST /api/sign/finish", srv.handleSignFinish)
	mux.HandleFunc("GET /api/verify", srv.handleVerify)

	if *demo {
		card, err := newDemoCard()
		if err != nil {
			log.Fatalf("create demo card: %v", err)
		}
		srv.card = card
		mux.HandleFunc("GET /api/demo-card/certificate", srv.handleDemoCardCert)
		mux.HandleFunc("POST /api/demo-card/sign", srv.handleDemoCardSign)
		log.Printf("DEMO MODE: /api/demo-card/* signing oracle is enabled — do not expose this server")
	}

	// Users review the exact bytes they are about to sign.
	mux.Handle("GET /pending/", http.StripPrefix("/pending/",
		http.FileServer(http.Dir(pendingDir))))
	mux.Handle("GET /signed/", http.StripPrefix("/signed/",
		http.FileServer(http.Dir(signedDir))))

	web, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("GET /", http.FileServer(http.FS(web)))

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second, // finish handler can wait on embedding
		IdleTimeout:       2 * time.Minute,
	}

	log.Printf("pending items in %s", filepath.Clean(pendingDir))
	if *tlsCert != "" {
		if *clientCA != "" {
			pool, err := signing.LoadCertPool(*clientCA)
			if err != nil {
				log.Fatalf("load -client-ca: %v", err)
			}
			httpServer.TLSConfig = &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  pool,
			}
			log.Printf("mTLS: TLS client certificates required")
		}
		log.Printf("pdf-sign listening on https://%s", *addr)
		log.Fatal(httpServer.ListenAndServeTLS(*tlsCert, *tlsKey))
	}
	log.Printf("pdf-sign listening on http://%s", *addr)
	log.Fatal(httpServer.ListenAndServe())
}

type server struct {
	signer    *signing.Manager
	locks     *itemLocks
	card      *demoCard // nil unless -demo
	demo      bool
	mtls      bool
	signRoots *x509.CertPool // nil unless -sign-ca
}

// itemLocks prevents two concurrent signing sessions for the same item.
type itemLocks struct {
	mu sync.Mutex
	m  map[string]bool
}

func newItemLocks() *itemLocks {
	return &itemLocks{m: make(map[string]bool)}
}

func (l *itemLocks) reserve(itemID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m[itemID] {
		return false
	}
	l.m[itemID] = true
	return true
}

func (l *itemLocks) release(itemID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, itemID)
}

// securityHeaders sets a CSP that blocks injected inline scripts — the
// approval page drives smart-card signing, so XSS there matters more than
// usual.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
