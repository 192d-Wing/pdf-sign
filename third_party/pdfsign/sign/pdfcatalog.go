package sign

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	"github.com/digitorus/pdf"
)

func (context *SignContext) createCatalog() ([]byte, error) {
	var catalog_buffer bytes.Buffer

	// Start the catalog object
	catalog_buffer.WriteString("<<\n")
	catalog_buffer.WriteString("  /Type /Catalog\n")

	// (Optional; PDF 1.4) The version of the PDF specification to which
	// the document conforms (for example, 1.4) if later than the version
	// specified in the file’s header (see 7.5.2, "File header"). If the header
	// specifies a later version, or if this entry is absent, the document
	// shall conform to the version specified in the header. This entry
	// enables a PDF processor to update the version using an incremental
	// update; see 7.5.6, "Incremental updates".
	// The value of this entry shall be a name object, not a number, and
	// therefore shall be preceded by a SOLIDUS (2Fh) character (/) when
	// written in the PDF file (for example, /1.4).
	//
	// If an incremental upgrade requires a version that is higher than specified by the document.
	// Ensure PDF version is at least 1.5 to support SigFlags in acroFormDict (1.4) and UF in the fileSpecDict (1.5)
	if v, err := strconv.ParseFloat(context.PDFReader.PDFVersion, 64); err == nil && v < 1.5 {
		catalog_buffer.WriteString("  /Version /1.5\n")
	}

	// Retrieve the root, its pointer and set the root string
	root := context.PDFReader.Trailer().Key("Root")
	rootPtr := root.GetPtr()
	context.CatalogData.RootString = strconv.Itoa(int(rootPtr.GetID())) + " " + strconv.Itoa(int(rootPtr.GetGen())) + " R"

	// Copy over existing catalog entries.
	//
	// Fork change (192d-Wing/pdf-sign): also skip /Perms. On reader-extended
	// forms (e.g. DAF 2096) /Perms holds an Adobe UR3 usage-rights
	// signature that our incremental update invalidates anyway; copying its
	// deeply-nested structure both serves no purpose and can drive the
	// lazy-resolving PDF parser into very deep recursion. /Names etc. are
	// indirect references and copy cheaply.
	for _, key := range root.Keys() {
		if key == "Type" || key == "AcroForm" || key == "Perms" {
			continue
		}
		_, _ = fmt.Fprintf(&catalog_buffer, "  /%s ", key)
		context.serializeCatalogEntry(&catalog_buffer, rootPtr.GetID(), root.Key(key))
		catalog_buffer.WriteString("\n")
	}

	// Start the AcroForm dictionary.
	//
	// Fork change (192d-Wing/pdf-sign): the upstream code rebuilt /Fields
	// with ONLY signature fields, silently orphaning every other form
	// field (fatal for real forms). Instead, preserve the original AcroForm
	// — all keys, all field references. serializeCatalogEntry emits proper
	// PDF syntax (parenthesized strings, "N 0 R" for indirect refs, so it
	// does not resolve into deep sub-objects like /DR).
	catalog_buffer.WriteString("  /AcroForm <<\n")

	acroForm := root.Key("AcroForm")
	acroFormID := rootPtr.GetID()
	if ptr := acroForm.GetPtr(); ptr.GetID() != 0 {
		acroFormID = ptr.GetID()
	}
	if !acroForm.IsNull() {
		for _, key := range acroForm.Keys() {
			switch key {
			case "Fields", "SigFlags":
				continue // rewritten below
			case "XFA":
				if context.SignData.DropXFA {
					continue
				}
			}
			_, _ = fmt.Fprintf(&catalog_buffer, "    /%s ", key)
			context.serializeCatalogEntry(&catalog_buffer, acroFormID, acroForm.Key(key))
			catalog_buffer.WriteString("\n")
		}
	}

	catalog_buffer.WriteString("    /Fields [")
	if !acroForm.IsNull() {
		originalFields := acroForm.Key("Fields")
		for i := 0; i < originalFields.Len(); i++ {
			ptr := originalFields.Index(i).GetPtr()
			catalog_buffer.WriteString(strconv.Itoa(int(ptr.GetID())) + " " + strconv.Itoa(int(ptr.GetGen())) + " R ")
		}
	}
	// A brand-new widget must be referenced from /Fields; a signature that
	// went into an existing field is already in the tree.
	if !context.signedExistingField {
		catalog_buffer.WriteString(strconv.Itoa(int(context.VisualSignData.objectId)) + " 0 R")
	}
	catalog_buffer.WriteString("]\n") // close Fields array

	// (Optional; deprecated in PDF 2.0) A flag specifying whether
	// to construct appearance streams and appearance
	// dictionaries for all widget annotations in the document (see
	// 12.7.4.3, "Variable text"). Default value: false. A PDF writer
	// shall include this key, with a value of true, if it has not
	// provided appearance streams for all visible widget
	// annotations present in the document.
	// if context.SignData.Visible {
	// 	catalog_buffer.WriteString(" /NeedAppearances true")
	// } else {
	// 	catalog_buffer.WriteString(" /NeedAppearances false")
	// }

	// Signature flags (Table 225)
	//
	// Bit position 1: SignaturesExist
	// If set, the document contains at least one signature field. This
	// flag allows an interactive PDF processor to enable user
	// interface items (such as menu items or push-buttons) related to
	// signature processing without having to scan the entire
	// document for the presence of signature fields.
	//
	// Bit position 2: AppendOnly
	// If set, the document contains signatures that may be invalidated
	// if the PDF file is saved (written) in a way that alters its previous
	// contents, as opposed to an incremental update. Merely updating
	// the PDF file by appending new information to the end of the
	// previous version is safe (see H.7, "Updating example").
	// Interactive PDF processors may use this flag to inform a user
	// requesting a full save that signatures will be invalidated and
	// require explicit confirmation before continuing with the
	// operation.
	//
	// Set SigFlags and Permissions based on Signature Type
	switch context.SignData.Signature.CertType {
	case CertificationSignature, ApprovalSignature, TimeStampSignature:
		catalog_buffer.WriteString("    /SigFlags 3\n")
	case UsageRightsSignature:
		catalog_buffer.WriteString("    /SigFlags 1\n")
	}

	// Finalize the AcroForm and Catalog object
	catalog_buffer.WriteString("  >>\n") // Close AcroForm
	catalog_buffer.WriteString(">>\n")   // Close Catalog

	return catalog_buffer.Bytes(), nil
}

// serializeCatalogEntry takes a pdf.Value and serializes it to the given writer.
func (context *SignContext) serializeCatalogEntry(w io.Writer, rootObjId uint32, value pdf.Value) {
	if ptr := value.GetPtr(); ptr.GetID() != rootObjId {
		// Indirect object
		_, _ = fmt.Fprintf(w, "%d %d R", ptr.GetID(), ptr.GetGen())
		return
	}

	// Direct object
	switch value.Kind() {
	case pdf.String:
		_, _ = fmt.Fprintf(w, "(%s)", value.RawString())
	case pdf.Null:
		_, _ = fmt.Fprint(w, "null")
	case pdf.Bool:
		if value.Bool() {
			_, _ = fmt.Fprint(w, "true")
		} else {
			_, _ = fmt.Fprint(w, "false")
		}
	case pdf.Integer:
		_, _ = fmt.Fprintf(w, "%d", value.Int64())
	case pdf.Real:
		_, _ = fmt.Fprintf(w, "%f", value.Float64())
	case pdf.Name:
		_, _ = fmt.Fprintf(w, "/%s", value.Name())
	case pdf.Dict:
		_, _ = fmt.Fprint(w, "<<")
		for idx, key := range value.Keys() {
			if idx > 0 {
				_, _ = fmt.Fprint(w, " ") // Space between items
			}
			_, _ = fmt.Fprintf(w, "/%s ", key)
			context.serializeCatalogEntry(w, rootObjId, value.Key(key))
		}
		_, _ = fmt.Fprint(w, ">>")
	case pdf.Array:
		_, _ = fmt.Fprint(w, "[")
		for idx := range value.Len() {
			if idx > 0 {
				_, _ = fmt.Fprint(w, " ") // Space between items
			}
			context.serializeCatalogEntry(w, rootObjId, value.Index(idx))
		}
		_, _ = fmt.Fprint(w, "]")
	case pdf.Stream:
		panic("stream cannot be a direct object")
	}
}
