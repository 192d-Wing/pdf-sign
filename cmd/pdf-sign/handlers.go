package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/192d-wing/pdf-sign/internal/signing"
	"github.com/digitorus/pdfsign/verify"
)

const maxRequestBody = 1 << 20 // 1 MiB: certs and signatures are a few KB

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON enforces a JSON content type (so plain-text cross-site form
// posts are rejected) and a body size cap before decoding into v.
//
// NIST 800-53r5 SI-10 (information input validation) and SC-5 (denial-of-
// service protection).
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

// authorizeSigningCert enforces the security policy on the certificate a
// client wants to sign with: it must be usable for signatures, chain to a
// trusted CA when -sign-ca is set, and belong to the mTLS-authenticated
// user when -client-ca is set. Returns the HTTP status to use on failure.
//
// NIST 800-53r5 IA-5(2) (PKI-based authentication: path validation to
// trust anchors), AC-3/AC-6 (access enforcement, least privilege: the
// CN match stops an authenticated user from signing as anyone but
// themselves), AU-10 (non-repudiation: the signature identity is bound
// to the authenticated session identity).
func (s *server) authorizeSigningCert(r *http.Request, cert *x509.Certificate) (int, error) {
	if err := signing.ValidateCert(cert, s.signRoots); err != nil {
		return http.StatusForbidden, err
	}
	if s.mtls {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return http.StatusForbidden, errors.New("client certificate required")
		}
		peer := r.TLS.PeerCertificates[0]
		// CAC/PIV authentication and signature certs share the subject CN;
		// signing on behalf of someone else is rejected.
		if !strings.EqualFold(peer.Subject.CommonName, cert.Subject.CommonName) {
			return http.StatusForbidden, fmt.Errorf(
				"signing certificate %q does not belong to authenticated user %q",
				cert.Subject.CommonName, peer.Subject.CommonName)
		}
	}
	return 0, nil
}

// GET /api/items
func (s *server) handleItems(w http.ResponseWriter, r *http.Request) {
	pending, signed, err := listItems()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pending": pending,
		"signed":  signed,
	})
}

// POST /api/sign/start {itemId, certificate(b64 DER)}
// → {token, digest(b64)}
func (s *server) handleSignStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ItemID      string `json:"itemId"`
		Certificate string `json:"certificate"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validItemID(req.ItemID) {
		writeError(w, http.StatusBadRequest, "invalid item id")
		return
	}
	certDER, err := base64.StdEncoding.DecodeString(req.Certificate)
	if err != nil {
		writeError(w, http.StatusBadRequest, "certificate is not valid base64")
		return
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		writeError(w, http.StatusBadRequest, "certificate is not valid DER: "+err.Error())
		return
	}
	if status, err := s.authorizeSigningCert(r, cert); err != nil {
		writeError(w, status, err.Error())
		return
	}

	pdfBytes, err := os.ReadFile(filepath.Join(pendingDir, req.ItemID+".pdf"))
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("unknown item %q", req.ItemID))
		return
	}

	if !s.locks.reserve(req.ItemID) {
		writeError(w, http.StatusConflict, "a signing session for this item is already in progress")
		return
	}
	sess, err := s.signer.Prepare(pdfBytes, cert, signing.Options{
		Owner:  req.ItemID,
		Name:   cert.Subject.CommonName,
		Reason: "Approved in pdf-sign",
	})
	if err != nil {
		s.locks.release(req.ItemID)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("sign/start item=%s signer=%q token=%s", req.ItemID, cert.Subject.CommonName, sess.Token[:8])

	writeJSON(w, http.StatusOK, map[string]string{
		"token":  sess.Token,
		"digest": base64.StdEncoding.EncodeToString(sess.Digest),
	})
}

// POST /api/sign/finish {token, signature(b64)}
// → {url}
func (s *server) handleSignFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token     string `json:"token"`
		Signature string `json:"signature"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil || len(signature) == 0 {
		writeError(w, http.StatusBadRequest, "signature is not valid base64")
		return
	}

	itemID, ok := s.signer.Owner(req.Token)
	if !ok {
		writeError(w, http.StatusNotFound, signing.ErrNotFound.Error())
		return
	}

	signedPDF, err := s.signer.Complete(req.Token, itemID, signature)
	if err != nil {
		if !errors.Is(err, signing.ErrNotFound) {
			s.locks.release(itemID)
		}
		status := http.StatusInternalServerError
		if errors.Is(err, signing.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	defer s.locks.release(itemID)

	if err := publishSigned(itemID, signedPDF); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	log.Printf("sign/finish item=%s -> %s", itemID, filepath.Join(signedDir, itemID+".pdf"))

	writeJSON(w, http.StatusOK, map[string]string{
		"url": "/signed/" + itemID + ".pdf",
	})
}

// publishSigned atomically places the signed PDF and retires the pending
// item. Written via a temp file so a failure never truncates an existing
// signed document.
func publishSigned(itemID string, signedPDF []byte) error {
	outPath := filepath.Join(signedDir, itemID+".pdf")
	tmpPath := outPath + ".tmp"
	if err := os.WriteFile(tmpPath, signedPDF, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("signed, but publishing the output failed: %w", err)
	}
	inPath := filepath.Join(pendingDir, itemID+".pdf")
	archive := filepath.Join(archiveDir, itemID+".pdf")
	if err := os.Rename(inPath, archive); err != nil {
		return fmt.Errorf("signed, but archiving pending file failed: %w", err)
	}
	return nil
}

// GET /api/verify?item=<id> — re-checks the signature on a signed PDF.
func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("item")
	if !validItemID(id) {
		writeError(w, http.StatusBadRequest, "invalid item id")
		return
	}
	f, err := os.Open(filepath.Join(signedDir, id+".pdf"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no signed PDF for that item")
		return
	}
	defer f.Close()

	opts := verify.DefaultVerifyOptions()
	// The demo card is self-signed, so demo mode trusts embedded certs.
	// Otherwise chains are validated against the system trust store.
	opts.AllowUntrustedRoots = s.demo
	opts.TrustSignatureTime = true // no TSA configured yet

	resp, err := verify.VerifyFileWithOptions(f, opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type signerSummary struct {
		Name           string `json:"name"`
		Reason         string `json:"reason"`
		ValidSignature bool   `json:"validSignature"`
		TrustedIssuer  bool   `json:"trustedIssuer"`
		TimeSource     string `json:"timeSource"`
	}
	summaries := []signerSummary{}
	for _, signer := range resp.Signers {
		summaries = append(summaries, signerSummary{
			Name:           signer.Name,
			Reason:         signer.Reason,
			ValidSignature: signer.ValidSignature,
			TrustedIssuer:  signer.TrustedIssuer,
			TimeSource:     signer.TimeSource,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"error":   resp.Error,
		"signers": summaries,
	})
}

// GET /api/demo-card/certificate — demo bridge: returns the "card" cert.
func (s *server) handleDemoCardCert(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"certificate": base64.StdEncoding.EncodeToString(s.card.cert.Raw),
		"subject":     s.card.cert.Subject.CommonName,
	})
}

// POST /api/demo-card/sign {digest(b64)} — demo bridge: signs the digest.
func (s *server) handleDemoCardSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Digest string `json:"digest"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	digest, err := base64.StdEncoding.DecodeString(req.Digest)
	if err != nil {
		writeError(w, http.StatusBadRequest, "digest is not valid base64")
		return
	}
	signature, err := s.card.signDigest(digest)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"signature": base64.StdEncoding.EncodeToString(signature),
	})
}
