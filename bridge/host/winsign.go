//go:build windows

package main

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	crypt32               = windows.NewLazySystemDLL("crypt32.dll")
	ncrypt                = windows.NewLazySystemDLL("ncrypt.dll")
	procAcquirePrivateKey = crypt32.NewProc("CryptAcquireCertificatePrivateKey")
	procNCryptSignHash    = ncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject  = ncrypt.NewProc("NCryptFreeObject")
)

const (
	cryptAcquireCacheFlag      = 0x00000001
	cryptAcquireSilentFlag     = 0x00000040
	cryptAcquireOnlyNCryptFlag = 0x00040000 // CNG only; legacy CSPs rejected
	ncryptPadPKCS1Flag         = 0x00000002
)

// BCRYPT_PKCS1_PADDING_INFO
type pkcs1PaddingInfo struct {
	pszAlgID *uint16
}

type certEntry struct {
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotAfter    string `json:"notAfter"`
	Thumbprint  string `json:"thumbprint"`
	Certificate string `json:"certificate"`       // base64 DER
	Warning     string `json:"warning,omitempty"` // shown to the user before signing
}

func openMyStore() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return 0, err
	}
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0, 0,
		windows.CERT_SYSTEM_STORE_CURRENT_USER|windows.CERT_STORE_READONLY_FLAG,
		uintptr(unsafe.Pointer(name)),
	)
	if err != nil {
		return 0, fmt.Errorf("open certificate store: %w", err)
	}
	return store, nil
}

func contextDER(ctx *windows.CertContext) []byte {
	der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
	return append([]byte(nil), der...)
}

// listSigningCertificates returns time-valid, digital-signature capable
// certificates from the user's MY store that have an accessible CNG
// private key (which is how smart-card certs surface on Windows).
func listSigningCertificates() ([]certEntry, error) {
	store, err := openMyStore()
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(store, 0)

	now := time.Now()
	entries := []certEntry{}
	scores := map[string]int{}

	var ctx *windows.CertContext
	for {
		ctx, err = windows.CertEnumCertificatesInStore(store, ctx)
		if err != nil {
			break // CRYPT_E_NOT_FOUND: end of store
		}
		der := contextDER(ctx)
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		if cert.IsCA || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			continue
		}
		if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			continue
		}
		if serverAuthOnly(cert) {
			continue // e.g. localhost dev certificates
		}
		if !hasNCryptKey(ctx) {
			continue
		}
		// SHA-1 here is the Windows certificate *thumbprint* — an identifier
		// used to look the cert up in the store, not a security function. It
		// is not used for signing or integrity, so its collision weakness is
		// irrelevant. nosemgrep: use-of-sha1
		sum := sha1.Sum(der)
		thumbprint := hex.EncodeToString(sum[:])
		scores[thumbprint] = signingScore(cert)
		entries = append(entries, certEntry{
			Subject:     cert.Subject.String(),
			Issuer:      cert.Issuer.String(),
			NotAfter:    cert.NotAfter.Format(time.RFC3339),
			Thumbprint:  thumbprint,
			Certificate: base64.StdEncoding.EncodeToString(der),
			Warning:     certWarning(cert, now),
		})
	}

	// Best signing candidate first: on PIV/CAC cards the *signature*
	// certificate carries the ContentCommitment (non-repudiation) bit,
	// while the authentication certificate does not.
	// NIST 800-53r5 AU-10 (non-repudiation): preferring the
	// non-repudiation certificate keeps document signatures attributable
	// under the issuing PKI's certificate policy.
	sort.SliceStable(entries, func(i, j int) bool {
		return scores[entries[i].Thumbprint] > scores[entries[j].Thumbprint]
	})
	return entries, nil
}

// certWarning flags conditions the user should see before signing, e.g.
// the CAC signature cert expired and the authentication cert would be
// used instead, or the cert is about to expire.
//
// NIST 800-53r5 IA-5(2) supporting: surfaces credential-lifetime and
// key-usage anomalies to the user instead of silently degrading.
func certWarning(cert *x509.Certificate, now time.Time) string {
	var warnings []string
	if cert.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		warnings = append(warnings, "certificate lacks the non-repudiation (signature) key usage — is this an authentication certificate?")
	}
	if remaining := cert.NotAfter.Sub(now); remaining < 14*24*time.Hour {
		warnings = append(warnings, fmt.Sprintf("certificate expires %s", cert.NotAfter.Format("2006-01-02")))
	}
	return strings.Join(warnings, "; ")
}

func signingScore(cert *x509.Certificate) int {
	score := 0
	if cert.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		score += 2
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageEmailProtection {
			score++
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}) { // document signing
			score += 2
		}
	}
	return score
}

func serverAuthOnly(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 {
		return false
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku != x509.ExtKeyUsageServerAuth {
			return false
		}
	}
	return len(cert.UnknownExtKeyUsage) == 0
}

// hasNCryptKey checks silently (no PIN prompt) whether the certificate has
// an associated CNG private key.
func hasNCryptKey(ctx *windows.CertContext) bool {
	var hKey windows.Handle
	var keySpec uint32
	var mustFree int32
	r, _, _ := procAcquirePrivateKey.Call(
		uintptr(unsafe.Pointer(ctx)),
		cryptAcquireCacheFlag|cryptAcquireSilentFlag|cryptAcquireOnlyNCryptFlag,
		0,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(&keySpec)),
		uintptr(unsafe.Pointer(&mustFree)),
	)
	if r == 0 {
		return false
	}
	if mustFree != 0 {
		_, _, _ = procNCryptFreeObject.Call(uintptr(hKey))
	}
	return true
}

// signDigest signs a SHA-256 digest with the private key of the cert
// identified by thumbprint. Windows shows the PIN prompt as needed.
// Returns PKCS#1 v1.5 for RSA keys, ASN.1 DER for ECDSA keys.
//
// NIST 800-53r5 IA-2(1)/(2) (multi-factor authentication): each signature
// requires the smart card (have) plus its PIN (know), enforced by the
// card through Windows CNG. SC-12 (key establishment and management):
// the private key never leaves the card — this process only ever holds a
// key handle. SC-13: signing is performed by the card/CNG cryptographic
// provider.
func signDigest(thumbprint string, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("expected a 32-byte SHA-256 digest")
	}
	want := strings.ToLower(thumbprint)

	store, err := openMyStore()
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(store, 0)

	var found *windows.CertContext
	var cert *x509.Certificate
	var ctx *windows.CertContext
	for {
		ctx, err = windows.CertEnumCertificatesInStore(store, ctx)
		if err != nil {
			break
		}
		der := contextDER(ctx)
		// SHA-1 thumbprint used only to match the requested certificate in
		// the store (an identifier, not a security function). nosemgrep: use-of-sha1
		sum := sha1.Sum(der)
		if hex.EncodeToString(sum[:]) == want {
			if cert, err = x509.ParseCertificate(der); err != nil {
				return nil, err
			}
			found = ctx // we own this context now (loop exits before re-enum)
			break
		}
	}
	if found == nil {
		return nil, errors.New("certificate not found in store")
	}
	defer windows.CertFreeCertificateContext(found)

	// Acquire the CNG key handle. Not silent: the card may prompt for a PIN.
	var hKey windows.Handle
	var keySpec uint32
	var mustFree int32
	r, _, callErr := procAcquirePrivateKey.Call(
		uintptr(unsafe.Pointer(found)),
		cryptAcquireCacheFlag|cryptAcquireOnlyNCryptFlag,
		0,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(&keySpec)),
		uintptr(unsafe.Pointer(&mustFree)),
	)
	if r == 0 {
		return nil, fmt.Errorf("acquire private key (CNG): %w", callErr)
	}
	if mustFree != 0 {
		defer procNCryptFreeObject.Call(uintptr(hKey))
	}

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		algID, err := windows.UTF16PtrFromString("SHA256")
		if err != nil {
			return nil, err
		}
		pad := pkcs1PaddingInfo{pszAlgID: algID}
		return ncryptSignHash(hKey, unsafe.Pointer(&pad), digest, ncryptPadPKCS1Flag)

	case x509.ECDSA:
		raw, err := ncryptSignHash(hKey, nil, digest, 0)
		if err != nil {
			return nil, err
		}
		return ecdsaRawToDER(raw)

	default:
		return nil, fmt.Errorf("unsupported key algorithm %s", cert.PublicKeyAlgorithm)
	}
}

func ncryptSignHash(hKey windows.Handle, padInfo unsafe.Pointer, digest []byte, flags uint32) ([]byte, error) {
	var size uint32
	status, _, _ := procNCryptSignHash.Call(
		uintptr(hKey),
		uintptr(padInfo),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		0, 0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if status != 0 {
		return nil, ncryptError("NCryptSignHash (size)", status)
	}

	sig := make([]byte, size)
	status, _, _ = procNCryptSignHash.Call(
		uintptr(hKey),
		uintptr(padInfo),
		uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if status != 0 {
		return nil, ncryptError("NCryptSignHash", status)
	}
	return sig[:size], nil
}

func ncryptError(op string, status uintptr) error {
	switch uint32(status) {
	case 0x8010006E, // SCARD_W_CANCELLED_BY_USER
		0x80090036: // NTE_USER_CANCELLED (CNG PIN dialog)
		return errors.New("PIN entry was cancelled")
	case 0x8010006B: // SCARD_W_WRONG_CHV
		return errors.New("wrong PIN")
	case 0x8010006C: // SCARD_W_CHV_BLOCKED
		return errors.New("card PIN is blocked")
	case 0x80100069: // SCARD_W_REMOVED_CARD
		return errors.New("smart card was removed")
	default:
		return fmt.Errorf("%s failed: 0x%08X", op, uint32(status))
	}
}

// ecdsaRawToDER converts CNG's raw r||s output to the ASN.1 DER form used
// in CMS signatures.
func ecdsaRawToDER(raw []byte) ([]byte, error) {
	if len(raw)%2 != 0 {
		return nil, errors.New("unexpected ECDSA signature length")
	}
	half := len(raw) / 2
	return asn1.Marshal(struct {
		R, S *big.Int
	}{
		R: new(big.Int).SetBytes(raw[:half]),
		S: new(big.Int).SetBytes(raw[half:]),
	})
}
