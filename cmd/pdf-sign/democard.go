package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// demoCard simulates the workstation-side signing bridge + smart card so
// the whole flow can be tested without hardware. It holds a software RSA
// key and signs digests exactly the way a PIV/CAC card would through
// Windows CNG: raw PKCS#1 v1.5 over a SHA-256 digest.
//
// In production, delete this file's endpoints and have the browser talk
// to Fortify or a native-messaging host instead — the private key must
// never live on the server.
type demoCard struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

// RFC 9336 Document Signing EKU, so the demo cert passes verification.
var oidDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}

func newDemoCard() (*demoCard, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Demo Signer (TEST ONLY)",
			Organization: []string{"pdf-sign development"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidDocumentSigning},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &demoCard{key: key, cert: cert}, nil
}

// signDigest mimics NCryptSignHash: PKCS#1 v1.5 over a raw SHA-256 digest.
func (c *demoCard) signDigest(digest []byte) ([]byte, error) {
	if len(digest) != crypto.SHA256.Size() {
		return nil, errors.New("expected a SHA-256 digest")
	}
	return rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, digest)
}
