// pdfsign-svc: standalone deferred-signing API service.
//
// Other websites integrate smart-card PDF signing by having their backend
// call this service; their frontend uses web/pdfsign-client.js + the
// bridge/ extension to produce the signature. The service never stores
// documents beyond the session TTL.
//
// API (JSON):
//
//	POST   /v1/signing-sessions
//	       {pdf, certificate, name?, reason?, location?}   (base64 pdf + DER cert)
//	  201  {sessionId, digest, expiresAt}
//
//	POST   /v1/signing-sessions/{id}/signature
//	       {signature}                                      (base64 raw signature)
//	  200  {pdf}                                            (base64 signed PDF)
//
//	DELETE /v1/signing-sessions/{id}
//	  204
//
// Authentication — one of two mutually exclusive modes:
//
//   - Production (default): mutual TLS. Requires -tls-cert, -tls-key and
//     -client-ca; every caller must present a client certificate issued by
//     the client CA, and the tenant identity is the client cert's CN.
//     Sessions are tenant-scoped: only the tenant that created a session
//     can complete or cancel it.
//
//   - Development (-dev): plain HTTP with a bearer token. The token is
//     read from the PDFSIGN_DEV_TOKEN environment variable or generated
//     and printed at startup. Bearer auth is refused unless -dev is set.
package main

import (
	"crypto/fips140"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/192d-wing/pdf-sign/internal/signing"
)

const (
	maxRequestBody = 32 << 20 // fits a ~24 MB PDF after base64 overhead
	sessionTTL     = 5 * time.Minute
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	dev := flag.Bool("dev", false, "development mode: plain HTTP with a bearer token instead of mTLS")
	signCA := flag.String("sign-ca", "", "PEM file of CA certificates that signing certs must chain to (required unless -dev)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file")
	tlsKey := flag.String("tls-key", "", "TLS private key file")
	clientCA := flag.String("client-ca", "", "PEM file of CAs for required TLS client certificates (tenant auth)")
	maxSessions := flag.Int("max-sessions", 32, "max concurrent signing sessions per tenant")
	tsaURL := flag.String("tsa", "", "RFC 3161 Time Stamping Authority URL for PAdES-T signatures (https, e.g. https://timestamp.digicert.com)")
	tsaInsecure := flag.Bool("tsa-allow-insecure", false, "permit a plaintext http TSA URL (internal networks only)")
	flag.Parse()

	// NIST 800-53r5 SC-13: report whether the Go FIPS 140-3 module is
	// active (build with GOFIPS140=v1.0.0; see docs/deployment.md) so the
	// mode is visible in the audit log.
	log.Printf("FIPS 140-3 mode: %v", fips140.Enabled())

	svc := &service{tsaURL: *tsaURL}
	if *tsaURL != "" {
		if err := signing.ValidateTSAURL(*tsaURL, *tsaInsecure); err != nil {
			log.Fatal(err)
		}
		log.Printf("RFC 3161 timestamps enabled via %s", *tsaURL)
	}

	// NIST 800-53r5 CM-7 (least functionality): development bearer-token
	// auth cannot coexist with production tenant auth, and production
	// refuses to start without mTLS + signing-cert validation configured
	// (SC-24: fail to a known secure state at startup, not at first use).
	if *dev {
		if *clientCA != "" {
			log.Fatal("-dev and -client-ca are mutually exclusive: bearer tokens are for development only")
		}
		svc.devToken = os.Getenv("PDFSIGN_DEV_TOKEN")
		if svc.devToken == "" {
			b := make([]byte, 24)
			if _, err := rand.Read(b); err != nil {
				log.Fatal(err)
			}
			svc.devToken = hex.EncodeToString(b)
			log.Printf("DEV MODE: bearer token %s", svc.devToken)
		} else {
			log.Printf("DEV MODE: bearer token from PDFSIGN_DEV_TOKEN")
		}
	} else {
		if *tlsCert == "" || *tlsKey == "" || *clientCA == "" {
			log.Fatal("production mode requires -tls-cert, -tls-key and -client-ca (or use -dev for development)")
		}
		if *signCA == "" {
			log.Fatal("production mode requires -sign-ca so signing certificates are validated")
		}
	}

	if *signCA != "" {
		pool, err := signing.LoadCertPool(*signCA)
		if err != nil {
			log.Fatalf("load -sign-ca: %v", err)
		}
		svc.signRoots = pool
	}

	svc.signer = signing.NewManager(sessionTTL, *maxSessions, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/signing-sessions", svc.handleCreate)
	mux.HandleFunc("POST /v1/signing-sessions/{id}/signature", svc.handleComplete)
	mux.HandleFunc("DELETE /v1/signing-sessions/{id}", svc.handleCancel)

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	if !*dev {
		pool, err := signing.LoadCertPool(*clientCA)
		if err != nil {
			log.Fatalf("load -client-ca: %v", err)
		}
		httpServer.TLSConfig = &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  pool,
		}
		log.Printf("pdfsign-svc listening on https://%s (mTLS tenant auth)", *addr)
		log.Fatal(httpServer.ListenAndServeTLS(*tlsCert, *tlsKey))
	}
	warnIfPlaintextExposed(*addr)
	log.Printf("pdfsign-svc listening on http://%s (DEV mode)", *addr)
	log.Fatal(httpServer.ListenAndServe())
}

// warnIfPlaintextExposed loudly flags a plaintext listener bound to a
// non-loopback address, which would expose bearer tokens and documents on
// the wire (SC-8). Dev mode is meant for loopback only.
func warnIfPlaintextExposed(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if !loopback {
		log.Printf("WARNING: serving plaintext HTTP on non-loopback address %q — traffic (including bearer tokens and documents) is unencrypted. Use production mode (mTLS) or bind to loopback behind a TLS-terminating proxy.", addr)
	}
}

type service struct {
	signer    *signing.Manager
	signRoots *x509.CertPool
	devToken  string // non-empty only in -dev mode
	tsaURL    string // empty = no RFC 3161 timestamp
}

// tenant authenticates the request and returns the tenant identity.
// mTLS mode: the client certificate CN (the TLS layer has already verified
// the chain). Dev mode: the fixed identity "dev" behind the bearer token.
//
// NIST 800-53r5 IA-9 (service identification and authentication):
// integrating backends authenticate with PKI client certificates over
// mutual TLS; IA-5(2): chain validation to -client-ca is enforced by
// tls.RequireAndVerifyClientCert before the request reaches handlers.
// The dev-token comparison is constant-time to avoid a timing oracle.
func (s *service) tenant(r *http.Request) (string, error) {
	if s.devToken != "" {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) > len(prefix) && auth[:len(prefix)] == prefix &&
			subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(s.devToken)) == 1 {
			return "dev", nil
		}
		return "", errors.New("missing or invalid bearer token")
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("client certificate required")
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON enforces content type and a body size cap before decoding.
//
// NIST 800-53r5 SI-10 (information input validation) and SC-5 (denial-of-
// service protection): strict media type, bounded request bodies.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errors.New("invalid or oversized JSON body")
	}
	return nil
}

// POST /v1/signing-sessions
func (s *service) handleCreate(w http.ResponseWriter, r *http.Request) {
	tenant, err := s.tenant(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req struct {
		PDF         string `json:"pdf"`
		Certificate string `json:"certificate"`
		Name        string `json:"name"`
		Reason      string `json:"reason"`
		Location    string `json:"location"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pdfBytes, err := base64.StdEncoding.DecodeString(req.PDF)
	if err != nil || len(pdfBytes) == 0 {
		writeError(w, http.StatusBadRequest, "pdf must be non-empty base64")
		return
	}
	certDER, err := base64.StdEncoding.DecodeString(req.Certificate)
	if err != nil {
		writeError(w, http.StatusBadRequest, "certificate is not valid base64")
		return
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		// Log the detail; return a generic message (avoid echoing library
		// internals to the caller).
		log.Printf("create tenant=%s: certificate parse error: %v", signing.SanitizeLogField(tenant), err)
		writeError(w, http.StatusBadRequest, "certificate is not valid DER")
		return
	}
	if err := signing.ValidateCert(cert, s.signRoots); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	name := req.Name
	if name == "" {
		name = cert.Subject.CommonName
	}
	sess, err := s.signer.Prepare(pdfBytes, cert, signing.Options{
		Owner:    tenant,
		Name:     name,
		Reason:   req.Reason,
		Location: req.Location,
		TSAURL:   s.tsaURL,
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	// NIST 800-53r5 AU-2/AU-3/AU-12 (audit events, content, generation):
	// every signature lifecycle event records who (tenant + signer CN),
	// what (session), and when (log timestamp). Ship stderr to the
	// organization's log aggregation for AU-4/AU-9 (storage, protection).
	log.Printf("create tenant=%s signer=%q session=%s pdf=%dB",
		signing.SanitizeLogField(tenant), signing.SanitizeLogField(cert.Subject.CommonName), sess.Token[:8], len(pdfBytes))

	writeJSON(w, http.StatusCreated, map[string]string{
		"sessionId": sess.Token,
		"digest":    base64.StdEncoding.EncodeToString(sess.Digest),
		"expiresAt": sess.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// POST /v1/signing-sessions/{id}/signature
func (s *service) handleComplete(w http.ResponseWriter, r *http.Request) {
	tenant, err := s.tenant(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req struct {
		Signature string `json:"signature"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil || len(signature) == 0 {
		writeError(w, http.StatusBadRequest, "signature must be non-empty base64")
		return
	}

	signedPDF, err := s.signer.Complete(r.PathValue("id"), tenant, signature)
	if err != nil {
		if errors.Is(err, signing.ErrNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	log.Printf("complete tenant=%s session=%s -> %dB", signing.SanitizeLogField(tenant), r.PathValue("id")[:8], len(signedPDF))

	writeJSON(w, http.StatusOK, map[string]string{
		"pdf": base64.StdEncoding.EncodeToString(signedPDF),
	})
}

// DELETE /v1/signing-sessions/{id}
func (s *service) handleCancel(w http.ResponseWriter, r *http.Request) {
	tenant, err := s.tenant(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.signer.Cancel(r.PathValue("id"), tenant); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
