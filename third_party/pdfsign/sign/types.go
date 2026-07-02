package sign

import (
	"crypto"
	"crypto/x509"
	"io"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/mattetti/filebuffer"
)

type CatalogData struct {
	ObjectId   uint32
	RootString string
}

type TSA struct {
	URL      string
	Username string
	Password string
}

type RevocationFunction func(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error

type SignData struct {
	Signature          SignDataSignature
	Signer             crypto.Signer
	DigestAlgorithm    crypto.Hash
	Certificate        *x509.Certificate
	CertificateChains  [][]*x509.Certificate
	TSA                TSA
	RevocationData     revocation.InfoArchival
	RevocationFunction RevocationFunction
	Appearance         Appearance

	// Fork addition (192d-Wing/pdf-sign):
	// SignatureField, when set, signs INTO this existing empty /FT /Sig
	// field (fully qualified name) instead of creating a new widget — for
	// pre-built forms with named signature blocks.
	SignatureField string
	// FillFields maps fully qualified AcroForm text-field names to values
	// written (with fresh appearance streams, read-only) in the same
	// incremental update as the signature — the basis for routed
	// multi-signature forms.
	FillFields map[string]string
	// DropXFA omits the /XFA entry when rewriting the AcroForm, turning a
	// static XFA form into a plain AcroForm so filled values render
	// deterministically in all viewers.
	DropXFA bool

	objectId uint32
}

// Appearance represents the appearance of the signature
type Appearance struct {
	Visible bool

	Page        uint32
	LowerLeftX  float64
	LowerLeftY  float64
	UpperRightX float64
	UpperRightY float64

	Image            []byte // Image data to use as signature appearance
	ImageAsWatermark bool   // If true, the text will be drawn over the image
}

type VisualSignData struct {
	pageObjectId uint32
	objectId     uint32
}

type InfoData struct {
	ObjectId uint32
}

//go:generate stringer -type=CertType
type CertType uint

const (
	CertificationSignature CertType = iota + 1
	ApprovalSignature
	UsageRightsSignature
	TimeStampSignature
)

//go:generate stringer -type=DocMDPPerm
type DocMDPPerm uint

const (
	DoNotAllowAnyChangesPerms DocMDPPerm = iota + 1
	AllowFillingExistingFormFieldsAndSignaturesPerms
	AllowFillingExistingFormFieldsAndSignaturesAndCRUDAnnotationsPerms
)

type SignDataSignature struct {
	CertType   CertType
	DocMDPPerm DocMDPPerm
	Info       SignDataSignatureInfo
}

type SignDataSignatureInfo struct {
	Name        string
	Location    string
	Reason      string
	ContactInfo string
	Date        time.Time
}

type SignContext struct {
	InputFile              io.ReadSeeker
	OutputFile             io.Writer
	OutputBuffer           *filebuffer.Buffer
	SignData               SignData
	CatalogData            CatalogData
	VisualSignData         VisualSignData
	InfoData               InfoData
	PDFReader              *pdf.Reader
	NewXrefStart           int64
	ByteRangeValues        []int64
	SignatureMaxLength     uint32
	SignatureMaxLengthBase uint32

	existingSignatures []SignData
	lastXrefID         uint32
	newXrefEntries     []xrefEntry
	updatedXrefEntries []xrefEntry

	// Fork addition (192d-Wing/pdf-sign): set when the signature went into
	// an existing field, so the catalog writer must not append a new field
	// reference to /Fields.
	signedExistingField bool
}
