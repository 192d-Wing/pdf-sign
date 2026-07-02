package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/go-pdf/fpdf"
)

type item struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// listItems returns pending and already-signed items by scanning the data
// directories. In a real system this would be a database-backed approval
// queue.
func listItems() (pending, signed []item, err error) {
	pending, err = scanPDFs(pendingDir, "")
	if err != nil {
		return nil, nil, err
	}
	signed, err = scanPDFs(signedDir, "/signed/")
	if err != nil {
		return nil, nil, err
	}
	return pending, signed, nil
}

func scanPDFs(dir, urlPrefix string) ([]item, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	items := []item{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pdf") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".pdf")
		it := item{ID: id, Name: e.Name()}
		if urlPrefix != "" {
			it.URL = urlPrefix + e.Name()
		}
		items = append(items, it)
	}
	return items, nil
}

// validItemID rejects anything that could escape the data directories.
func validItemID(id string) bool {
	return id != "" && id == filepath.Base(id) && !strings.Contains(id, "..") &&
		!strings.ContainsAny(id, `/\`)
}

// ensureSamplePDFs generates a couple of pending documents on first run so
// the demo has something to approve.
func ensureSamplePDFs(dir string) error {
	existing, err := scanPDFs(dir, "")
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return nil
	}

	samples := []struct {
		file, title string
		body        []string
	}{
		{
			file:  "purchase-order-4211.pdf",
			title: "Purchase Order #4211",
			body: []string{
				"Vendor: Example Hardware Co.",
				"Items: 12x developer laptops",
				"Total: $18,240.00",
				"",
				"This purchase order requires an approval signature.",
			},
		},
		{
			file:  "contract-renewal-acme.pdf",
			title: "Contract Renewal - Acme Corp",
			body: []string{
				"Term: 2026-08-01 through 2027-07-31",
				"Annual value: $96,000.00",
				"",
				"This contract renewal requires an approval signature.",
			},
		},
	}

	for _, s := range samples {
		pdf := fpdf.New("P", "mm", "Letter", "")
		pdf.AddPage()
		pdf.SetFont("Helvetica", "B", 16)
		pdf.Cell(0, 12, s.title)
		pdf.Ln(16)
		pdf.SetFont("Helvetica", "", 11)
		for _, line := range s.body {
			pdf.Cell(0, 7, line)
			pdf.Ln(7)
		}
		if err := pdf.OutputFileAndClose(filepath.Join(dir, s.file)); err != nil {
			return err
		}
	}
	return nil
}
