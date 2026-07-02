package sign

// Fork addition (192d-Wing/pdf-sign): fill existing AcroForm text fields in
// the same incremental update as the signature. This is what makes routed
// multi-signature forms work: each signer's identity line lands in the
// form's own named field and is covered by that signer's signature, while
// earlier signatures stay valid because everything rides in one
// incremental revision.

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/digitorus/pdf"
)

// fillTextFields writes SignData.FillFields values into their existing
// AcroForm text fields: /V is set on the field, a fresh appearance stream
// is attached to its widget(s), and the field is marked read-only so
// later steps cannot alter what this signer attested to.
func (context *SignContext) fillTextFields() error {
	if len(context.SignData.FillFields) == 0 {
		return nil
	}

	acro := context.PDFReader.Trailer().Key("Root").Key("AcroForm")
	if acro.IsNull() {
		return fmt.Errorf("fill fields: document has no AcroForm")
	}

	// One shared simple font object for all appearance streams.
	fontID, err := context.addObject([]byte(
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"))
	if err != nil {
		return fmt.Errorf("fill fields: add font object: %w", err)
	}

	for name, value := range context.SignData.FillFields {
		field, ok := findFieldByName(acro.Key("Fields"), "", name)
		if !ok {
			return fmt.Errorf("fill fields: field %q not found in AcroForm", name)
		}
		if err := context.fillOneField(field, value, fontID); err != nil {
			return fmt.Errorf("fill fields: %q: %w", name, err)
		}
	}
	return nil
}

// findFieldByName walks the AcroForm field tree matching the fully
// qualified name (partial names joined with '.').
func findFieldByName(fields pdf.Value, prefix, want string) (pdf.Value, bool) {
	for i := 0; i < fields.Len(); i++ {
		fld := fields.Index(i)
		name := fld.Key("T").Text()
		full := name
		if prefix != "" && name != "" {
			full = prefix + "." + name
		} else if prefix != "" {
			full = prefix
		}
		if full == want {
			return fld, true
		}
		kids := fld.Key("Kids")
		if kids.Len() > 0 && strings.HasPrefix(want, full) {
			if found, ok := findFieldByName(kids, full, want); ok {
				return found, ok
			}
		}
	}
	return pdf.Value{}, false
}

func (context *SignContext) fillOneField(field pdf.Value, value string, fontID uint32) error {
	ft := field.Key("FT").Name()
	if ft != "Tx" {
		return fmt.Errorf("field type /%s is not a text field", ft)
	}
	if !field.Key("V").IsNull() && field.Key("V").Text() != "" {
		return fmt.Errorf("field already has a value")
	}
	fieldPtr := field.GetPtr()
	if fieldPtr.GetGen() != 0 {
		return fmt.Errorf("unsupported object generation %d", fieldPtr.GetGen())
	}

	// Merged field+widget (has /Rect) is the common case; otherwise the
	// widgets are the /Kids.
	if field.Key("Rect").IsNull() {
		return fmt.Errorf("field has no /Rect (separate widget kids are not supported yet)")
	}

	rect := field.Key("Rect")
	llx, lly := rect.Index(0).Float64(), rect.Index(1).Float64()
	urx, ury := rect.Index(2).Float64(), rect.Index(3).Float64()
	width, height := urx-llx, ury-lly
	if width < 0 {
		width = -width
	}
	if height < 0 {
		height = -height
	}

	apID, err := context.addFieldAppearance(width, height, value, fontID)
	if err != nil {
		return err
	}

	// Rewrite the field object: copy every existing key except the ones we
	// set, so inherited behavior (DA, Q, MaxLen, P, ...) is preserved.
	var buf bytes.Buffer
	buf.WriteString("<<\n")
	skip := map[string]bool{"V": true, "AP": true, "Ff": true, "AS": true}
	for _, key := range field.Keys() {
		if skip[key] {
			continue
		}
		fmt.Fprintf(&buf, "  /%s ", key)
		context.serializeCatalogEntry(&buf, fieldPtr.GetID(), field.Key(key))
		buf.WriteString("\n")
	}
	fmt.Fprintf(&buf, "  /V %s\n", pdfString(value))
	// Read-only (bit 1): later route steps must not edit signed content.
	fmt.Fprintf(&buf, "  /Ff %d\n", field.Key("Ff").Int64()|1)
	fmt.Fprintf(&buf, "  /AP << /N %d 0 R >>\n", apID)
	buf.WriteString(">>\n")

	if err := context.updateObject(fieldPtr.GetID(), buf.Bytes()); err != nil {
		return fmt.Errorf("update field object %d: %w", fieldPtr.GetID(), err)
	}
	return nil
}

// addFieldAppearance creates a variable-text appearance stream for a
// filled text field.
func (context *SignContext) addFieldAppearance(width, height float64, value string, fontID uint32) (uint32, error) {
	fontSize := 9.0
	if height > 0 && height < fontSize+4 {
		fontSize = height - 4
		if fontSize < 4 {
			fontSize = 4
		}
	}
	// Vertically center the baseline, approximately.
	baseline := (height-fontSize)/2 + fontSize*0.25
	if baseline < 2 {
		baseline = 2
	}

	// Content stream text must stay single-byte for WinAnsi; drop anything
	// outside ASCII (signer identity lines are ASCII).
	clean := make([]rune, 0, len(value))
	for _, r := range value {
		if r >= 0x20 && r < 0x7f {
			clean = append(clean, r)
		}
	}

	var content bytes.Buffer
	content.WriteString("/Tx BMC\nq\nBT\n")
	fmt.Fprintf(&content, "/Helv %.1f Tf\n0 g\n", fontSize)
	fmt.Fprintf(&content, "2 %.2f Td\n", baseline)
	fmt.Fprintf(&content, "%s Tj\n", pdfString(string(clean)))
	content.WriteString("ET\nQ\nEMC\n")

	var obj bytes.Buffer
	obj.WriteString("<<\n  /Type /XObject\n  /Subtype /Form\n  /FormType 1\n")
	fmt.Fprintf(&obj, "  /BBox [0 0 %f %f]\n", width, height)
	obj.WriteString("  /Matrix [1 0 0 1 0 0]\n")
	fmt.Fprintf(&obj, "  /Resources << /Font << /Helv %d 0 R >> >>\n", fontID)
	fmt.Fprintf(&obj, "  /Length %d\n", content.Len())
	obj.WriteString(">>\nstream\n")
	obj.Write(content.Bytes())
	obj.WriteString("\nendstream")

	return context.addObject(obj.Bytes())
}
