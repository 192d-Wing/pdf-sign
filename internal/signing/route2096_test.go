package signing

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/verify"
)

// TestRouted2096 drives a real DAF 2096 through a 3-step signing route:
// each step fills that signer's text field and applies their signature in
// one incremental update, so all three signatures stay valid.
//
// Requires a DECRYPTED copy of the form (pdfcpu decrypt); set:
//
//	PDF2096=path\to\daf2096-decrypted.pdf go test ./internal/signing -run TestRouted2096
//
// Optionally PDF2096_OUT=path to keep the final signed PDF for manual
// inspection in Adobe.
func TestRouted2096(t *testing.T) {
	src := os.Getenv("PDF2096")
	if src == "" {
		t.Skip("PDF2096 not set; skipping routed-form integration test")
	}
	pdfBytes, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}

	const page1 = "topmostSubform[0].Page1[0]."
	steps := []struct {
		signer string
		field  string
	}{
		{"MEMBER.TEST.ONE.1000000001", page1 + "SIGNATURE_OF_MEMBER[0]"},
		{"SUPERVISOR.TEST.TWO.1000000002", page1 + "Signature8[0]"},
		{"APPROVER.TEST.THREE.1000000003", page1 + "Signature9[0]"},
	}

	mgr := NewManager(time.Minute, 0, nil)
	current := pdfBytes

	// Each step signs INTO that signer's existing /FT /Sig field and also
	// fills their date text field in the same incremental update.
	dates := []string{
		page1 + "Date6_af_date[0]",
		page1 + "Date7_af_date[0]",
		page1 + "Date1_af_date[0]",
	}
	for i, step := range steps {
		key, cert := testSigner(t, step.signer)
		sess, err := mgr.Prepare(current, cert, Options{
			Owner:          "route-test",
			Name:           step.signer,
			Reason:         "Routed approval step " + string(rune('1'+i)),
			SignatureField: step.field,
			FillFields: map[string]string{
				dates[i]: time.Now().Format("02 Jan 2006"),
			},
			DropXFA: true,
		})
		if err != nil {
			t.Fatalf("step %d Prepare: %v", i+1, err)
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sess.Digest)
		if err != nil {
			t.Fatal(err)
		}
		current, err = mgr.Complete(sess.Token, "route-test", sig)
		if err != nil {
			t.Fatalf("step %d Complete: %v", i+1, err)
		}
		t.Logf("step %d signed by %s: %d bytes", i+1, step.signer, len(current))
	}

	// All three signatures must verify.
	opts := verify.DefaultVerifyOptions()
	opts.AllowUntrustedRoots = true // self-signed test certs
	opts.TrustSignatureTime = true
	resp, err := verify.VerifyWithOptions(bytes.NewReader(current), int64(len(current)), opts)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(resp.Signers) != 3 {
		t.Fatalf("want 3 signers, got %d", len(resp.Signers))
	}
	for i, s := range resp.Signers {
		if !s.ValidSignature {
			t.Errorf("signature %d (%s) is not valid", i+1, s.Name)
		}
	}

	// The filled fields must carry their values, and the rest of the form
	// must have survived (AcroForm preservation).
	rdr, err := pdf.NewReader(bytes.NewReader(current), int64(len(current)))
	if err != nil {
		t.Fatalf("parse signed output: %v", err)
	}
	acro := rdr.Trailer().Key("Root").Key("AcroForm")
	if !acro.Key("XFA").IsNull() {
		t.Error("XFA should have been dropped")
	}
	total := 0
	for i, step := range steps {
		fld, ok := findField(acro.Key("Fields"), "", step.field, &total)
		if !ok {
			t.Fatalf("signature field %q missing from signed output", step.field)
		}
		if fld.Key("V").IsNull() {
			t.Errorf("signature field %q has no /V (not signed into)", step.field)
		} else if typ := fld.Key("V").Key("Type").Name(); typ != "Sig" {
			t.Errorf("signature field %q /V is /%s, want /Sig", step.field, typ)
		} else {
			t.Logf("signature field %q filled (signed)", step.field)
		}

		dfld, ok := findField(acro.Key("Fields"), "", dates[i], &total)
		if !ok {
			t.Fatalf("date field %q missing from signed output", dates[i])
		}
		if got := dfld.Key("V").Text(); got == "" {
			t.Errorf("date field %q has empty /V", dates[i])
		} else {
			t.Logf("date field %q = %q", dates[i], got)
		}
		if dfld.Key("Ff").Int64()&1 == 0 {
			t.Errorf("date field %q not marked read-only", dates[i])
		}
	}
	if total < 100 {
		t.Errorf("AcroForm field tree looks truncated: walked only %d nodes", total)
	}

	if out := os.Getenv("PDF2096_OUT"); out != "" {
		if err := os.WriteFile(out, current, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote signed output to %s", out)
	}
}

func findField(fields pdf.Value, prefix, want string, count *int) (pdf.Value, bool) {
	for i := 0; i < fields.Len(); i++ {
		fld := fields.Index(i)
		*count++
		name := fld.Key("T").Text()
		full := name
		if prefix != "" {
			full = prefix + "." + name
		}
		if full == want {
			return fld, true
		}
		if kids := fld.Key("Kids"); kids.Len() > 0 {
			if found, ok := findField(kids, full, want, count); ok {
				return found, ok
			}
		}
	}
	return pdf.Value{}, false
}

func testSigner(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}
