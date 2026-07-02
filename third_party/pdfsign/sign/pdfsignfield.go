package sign

// Fork addition (192d-Wing/pdf-sign): sign INTO an existing empty
// signature field (/FT /Sig) instead of creating a new widget. This is
// how pre-built government/enterprise forms with named signature blocks
// (e.g. DAF 2096) are routed: each signer fills their own field, the
// widget is already on the page and in the AcroForm tree, and everything
// rides in one incremental update.

import (
	"bytes"
	"fmt"
)

// signIntoExistingField updates the named, empty /FT /Sig field so its /V
// points at this revision's signature dictionary, attaching a visible
// appearance sized to the field's existing /Rect. It replaces the
// create-new-widget path: no page /Annots update and no AcroForm /Fields
// append is needed because the widget already exists in both.
func (context *SignContext) signIntoExistingField() error {
	name := context.SignData.SignatureField

	acro := context.PDFReader.Trailer().Key("Root").Key("AcroForm")
	if acro.IsNull() {
		return fmt.Errorf("sign into field: document has no AcroForm")
	}
	field, ok := findFieldByName(acro.Key("Fields"), "", name)
	if !ok {
		return fmt.Errorf("sign into field: field %q not found in AcroForm", name)
	}
	if ft := field.Key("FT").Name(); ft != "Sig" {
		return fmt.Errorf("sign into field: %q is /FT /%s, not a signature field", name, ft)
	}
	if !field.Key("V").IsNull() {
		return fmt.Errorf("sign into field: %q is already signed", name)
	}
	fieldPtr := field.GetPtr()
	if fieldPtr.GetGen() != 0 {
		return fmt.Errorf("sign into field: unsupported object generation %d", fieldPtr.GetGen())
	}
	if field.Key("Rect").IsNull() {
		return fmt.Errorf("sign into field: %q has no /Rect (separate widget kids are not supported yet)", name)
	}

	rect := field.Key("Rect")
	r := [4]float64{
		rect.Index(0).Float64(), rect.Index(1).Float64(),
		rect.Index(2).Float64(), rect.Index(3).Float64(),
	}
	visible := (r[2]-r[0]) >= 1 && (r[3]-r[1]) >= 1

	var apID uint32
	if visible {
		appearance, err := context.createAppearance(r)
		if err != nil {
			return fmt.Errorf("sign into field: appearance: %w", err)
		}
		apID, err = context.addObject(appearance)
		if err != nil {
			return fmt.Errorf("sign into field: add appearance object: %w", err)
		}
	}

	// Rewrite the field object preserving everything except the entries we
	// set (/V to the new signature dictionary, /AP to the new appearance).
	var buf bytes.Buffer
	buf.WriteString("<<\n")
	skip := map[string]bool{"V": true, "AP": true, "AS": true}
	for _, key := range field.Keys() {
		if skip[key] {
			continue
		}
		fmt.Fprintf(&buf, "  /%s ", key)
		context.serializeCatalogEntry(&buf, fieldPtr.GetID(), field.Key(key))
		buf.WriteString("\n")
	}
	fmt.Fprintf(&buf, "  /V %d 0 R\n", context.SignData.objectId)
	if visible {
		fmt.Fprintf(&buf, "  /AP << /N %d 0 R >>\n", apID)
	}
	buf.WriteString(">>\n")

	if err := context.updateObject(fieldPtr.GetID(), buf.Bytes()); err != nil {
		return fmt.Errorf("sign into field: update field object %d: %w", fieldPtr.GetID(), err)
	}

	// Tell the catalog writer that no new field reference must be added.
	context.signedExistingField = true
	return nil
}
