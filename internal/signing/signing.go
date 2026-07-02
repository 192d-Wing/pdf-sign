// Package signing implements deferred (remote-hash) PAdES signing of PDFs.
//
// The caller supplies the PDF bytes and the signer's certificate; the
// package prepares the signature, surfaces the SHA-256 digest of the CMS
// signed attributes, and parks the signing operation until the caller
// delivers the raw signature produced elsewhere (typically by a smart
// card on the user's workstation). The returned signature is verified
// against the certificate before it is embedded.
//
// A Manager holds the in-flight sessions. Sessions are tagged with an
// Owner string chosen by the caller (a tenant identity, a user, or an
// application-specific key); Complete and Cancel require the same owner,
// and per-owner concurrency can be capped.
//
// NIST 800-53r5: this package is the primary implementation point for
// AU-10 (non-repudiation) — documents are bound to the signer's PKI
// identity via PAdES digital signatures — and SC-13 (cryptographic
// protection: SHA-256 digests, RSA/ECDSA verification via Go stdlib
// crypto). Per-control annotations appear at the enforcing functions;
// see docs/nist-800-53-mapping.md for the consolidated ATO matrix.
package signing

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/sign"
)

const (
	digestWait  = 30 * time.Second // Prepare: max wait for the digest to surface
	finishWait  = 30 * time.Second // Complete: max wait for embedding to finish
	tokenLength = 16
)

// ErrNotFound is returned by Complete and Cancel when no session matches
// the token/owner pair (unknown, expired, or owned by someone else).
var ErrNotFound = errors.New("unknown or expired signing session")

// Options configures one signing session.
type Options struct {
	Owner    string // required for multi-tenant use; must be repeated on Complete/Cancel
	Name     string // signer name shown in the PDF signature dictionary
	Reason   string
	Location string
}

// Session is an in-flight deferred signature.
type Session struct {
	Token     string
	Owner     string
	Digest    []byte // SHA-256 of the CMS signed attributes; sign this
	ExpiresAt time.Time

	pub    crypto.PublicKey
	sigCh  chan []byte
	doneCh chan error
	out    *bytes.Buffer
}

// externalSigner implements crypto.Signer without holding a key. When the
// pkcs7 layer asks it to sign the digest of the CMS signed attributes, it
// publishes the digest on digestCh and blocks until Complete delivers the
// signature on sigCh (or the session is cancelled by closing sigCh).
type externalSigner struct {
	pub      crypto.PublicKey
	digestCh chan []byte
	sigCh    chan []byte
}

func (e *externalSigner) Public() crypto.PublicKey { return e.pub }

func (e *externalSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	e.digestCh <- digest
	sig, ok := <-e.sigCh
	if !ok {
		return nil, errors.New("signing session cancelled")
	}
	return sig, nil
}

// Manager tracks in-flight sessions and expires abandoned ones.
type Manager struct {
	ttl         time.Duration
	maxPerOwner int                       // 0 = unlimited
	onExpire    func(token, owner string) // called after the janitor cancels a session
	mu          sync.Mutex
	sessions    map[string]*Session
}

// NewManager creates a Manager and starts its expiry janitor. ttl bounds
// how long a prepared session may wait for its signature; onExpire (may be
// nil) lets the caller release any state keyed to the session.
//
// NIST 800-53r5 AC-12 (session termination): abandoned signing sessions
// are terminated automatically at ttl. SC-5(2) (resource availability):
// maxPerOwner caps concurrent sessions — and therefore parked goroutines
// and in-memory documents — per owner/tenant.
func NewManager(ttl time.Duration, maxPerOwner int, onExpire func(token, owner string)) *Manager {
	m := &Manager{
		ttl:         ttl,
		maxPerOwner: maxPerOwner,
		onExpire:    onExpire,
		sessions:    make(map[string]*Session),
	}
	go m.janitor()
	return m
}

func (m *Manager) janitor() {
	for range time.Tick(time.Minute) {
		now := time.Now()
		m.mu.Lock()
		var expired []*Session
		for token, sess := range m.sessions {
			if now.After(sess.ExpiresAt) {
				expired = append(expired, sess)
				delete(m.sessions, token)
			}
		}
		m.mu.Unlock()
		for _, sess := range expired {
			close(sess.sigCh) // externalSigner.Sign returns an error
			<-sess.doneCh
			if m.onExpire != nil {
				m.onExpire(sess.Token, sess.Owner)
			}
		}
	}
}

// Owner reports the owner of an active session, so callers that key state
// by owner can resolve a bare token.
func (m *Manager) Owner(token string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[token]
	if !ok {
		return "", false
	}
	return sess.Owner, true
}

// Prepare starts a deferred signature over pdfBytes and returns once the
// digest to be signed is known. The session stays open until Complete,
// Cancel, or expiry.
func (m *Manager) Prepare(pdfBytes []byte, cert *x509.Certificate, opts Options) (*Session, error) {
	if m.maxPerOwner > 0 {
		m.mu.Lock()
		count := 0
		for _, sess := range m.sessions {
			if sess.Owner == opts.Owner {
				count++
			}
		}
		m.mu.Unlock()
		if count >= m.maxPerOwner {
			return nil, fmt.Errorf("too many concurrent signing sessions for %q (max %d)", opts.Owner, m.maxPerOwner)
		}
	}

	reader := bytes.NewReader(pdfBytes)
	rdr, err := pdf.NewReader(reader, int64(len(pdfBytes)))
	if err != nil {
		return nil, fmt.Errorf("parse PDF: %w", err)
	}

	token, err := newToken()
	if err != nil {
		return nil, err
	}

	signer := &externalSigner{
		pub:      cert.PublicKey,
		digestCh: make(chan []byte, 1),
		sigCh:    make(chan []byte),
	}
	sess := &Session{
		Token:     token,
		Owner:     opts.Owner,
		ExpiresAt: time.Now().Add(m.ttl),
		pub:       cert.PublicKey,
		sigCh:     signer.sigCh,
		doneCh:    make(chan error, 1),
		out:       &bytes.Buffer{},
	}

	signData := sign.SignData{
		Signature: sign.SignDataSignature{
			CertType:   sign.ApprovalSignature,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
			Info: sign.SignDataSignatureInfo{
				Name:     opts.Name,
				Reason:   opts.Reason,
				Location: opts.Location,
				Date:     time.Now(),
			},
		},
		Signer:          signer,
		DigestAlgorithm: crypto.SHA256,
		Certificate:     cert,
	}

	go func() {
		// A panic inside the PDF library must not kill the process or
		// strand a Complete caller.
		defer func() {
			if r := recover(); r != nil {
				sess.doneCh <- fmt.Errorf("signing panicked: %v", r)
			}
		}()
		sess.doneCh <- sign.Sign(reader, sess.out, rdr, int64(len(pdfBytes)), signData)
	}()

	select {
	case digest := <-signer.digestCh:
		sess.Digest = digest
		m.mu.Lock()
		m.sessions[token] = sess
		m.mu.Unlock()
		return sess, nil
	case err := <-sess.doneCh:
		// Signing failed before it ever needed the signature.
		if err == nil {
			err = errors.New("signing finished without requesting a signature")
		}
		return nil, err
	case <-time.After(digestWait):
		close(signer.sigCh)
		<-sess.doneCh
		return nil, errors.New("timed out preparing signature")
	}
}

// Complete verifies the signature against the session's certificate,
// resumes the parked signing operation, and returns the signed PDF.
// On any error the session is closed; the caller's document is untouched
// because all work happens on in-memory copies.
func (m *Manager) Complete(token, owner string, signature []byte) ([]byte, error) {
	sess := m.takeOwned(token, owner)
	if sess == nil {
		return nil, ErrNotFound
	}

	if err := verifyRawSignature(sess.pub, sess.Digest, signature); err != nil {
		close(sess.sigCh)
		<-sess.doneCh
		return nil, fmt.Errorf("signature does not verify against the submitted certificate: %w", err)
	}

	select {
	case sess.sigCh <- signature:
	case <-time.After(finishWait):
		// Only possible if the signing goroutine died; doneCh has the why.
		select {
		case err := <-sess.doneCh:
			return nil, fmt.Errorf("signing session is no longer active: %w", err)
		default:
			return nil, errors.New("signing session is no longer active")
		}
	}

	select {
	case err := <-sess.doneCh:
		if err != nil {
			return nil, err
		}
		return sess.out.Bytes(), nil
	case <-time.After(finishWait):
		return nil, errors.New("timed out embedding signature")
	}
}

// Cancel aborts an in-flight session.
func (m *Manager) Cancel(token, owner string) error {
	sess := m.takeOwned(token, owner)
	if sess == nil {
		return ErrNotFound
	}
	close(sess.sigCh)
	<-sess.doneCh
	return nil
}

// takeOwned removes and returns the session iff the owner matches; exactly
// one caller ever obtains a given session, which makes closing or sending
// on sigCh race-free.
//
// NIST 800-53r5 AC-3 (access enforcement): the owner check scopes every
// Complete/Cancel to the identity that created the session, so one tenant
// can never finish or abort another tenant's signature.
func (m *Manager) takeOwned(token, owner string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[token]
	if !ok || sess.Owner != owner {
		return nil
	}
	delete(m.sessions, token)
	return sess
}

// verifyRawSignature checks that a signature verifies against the public
// key of the certificate the session was prepared with. Without this,
// garbage from a broken (or malicious) client would be embedded into the
// document.
//
// NIST 800-53r5 SI-7 (software and information integrity) and SI-10
// (input validation): client-supplied signature bytes are
// cryptographically validated before being embedded into the record
// copy. SC-13: verification uses FIPS-approved algorithms (RSA PKCS#1
// v1.5 / ECDSA with SHA-256).
func verifyRawSignature(pub crypto.PublicKey, digest, signature []byte) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, signature) {
			return errors.New("ECDSA verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
}

// ValidateCert enforces the certificate policy for signing: digital
// signature key usage, and (when roots is non-nil) a chain to a trusted
// CA.
//
// NIST 800-53r5 IA-5(2) (PKI-based authentication): certification-path
// validation to organization-configured trust anchors before any signing
// work is performed. SC-17 (PKI certificates): the trust anchors are the
// organization's approved CAs supplied via -sign-ca.
func ValidateCert(cert *x509.Certificate, roots *x509.CertPool) error {
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("certificate does not allow digital signatures")
	}
	if roots != nil {
		_, err := cert.Verify(x509.VerifyOptions{
			Roots: roots,
			// Without this, Verify defaults to requiring the TLS server
			// EKU, which signing certs never have.
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			return fmt.Errorf("certificate does not chain to a trusted signing CA: %w", err)
		}
	}
	return nil
}

// LoadCertPool reads a PEM bundle into a certificate pool.
func LoadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, nil
}

// newToken generates the session identifier.
//
// NIST 800-53r5 SC-23(3) (unique system-generated session identifiers):
// 128 bits from crypto/rand; identifiers are single-use (takeOwned
// removes them) and expire at the session TTL.
func newToken() (string, error) {
	b := make([]byte, tokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
