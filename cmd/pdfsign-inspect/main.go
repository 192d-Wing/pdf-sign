// pdfsign-inspect: dump a PDF's AcroForm structure — field names, types,
// rects, filled/empty state, XFA presence. Used to plan routed signing of
// multi-signature forms (e.g. DAF 2096).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/digitorus/pdf"
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatal("usage: pdfsign-inspect <file.pdf>")
	}
	path := flag.Arg(0)

	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	fi, _ := f.Stat()

	rdr, err := pdf.NewReader(f, fi.Size())
	if err != nil {
		log.Fatalf("parse: %v", err)
	}

	root := rdr.Trailer().Key("Root")
	acro := root.Key("AcroForm")
	if acro.IsNull() {
		fmt.Println("no AcroForm")
		return
	}

	fmt.Println("AcroForm keys:")
	for _, k := range acro.Keys() {
		switch k {
		case "Fields":
			fmt.Printf("  /Fields (%d entries)\n", acro.Key(k).Len())
		case "XFA":
			fmt.Printf("  /XFA PRESENT (kind=%v)\n", acro.Key(k).Kind())
		default:
			fmt.Printf("  /%s = %s\n", k, trunc(acro.Key(k).String(), 60))
		}
	}

	fields := acro.Key("Fields")
	fmt.Printf("\nFields (%d):\n", fields.Len())
	for i := 0; i < fields.Len(); i++ {
		dumpField(fields.Index(i), "", i)
	}
}

func dumpField(fld pdf.Value, parent string, idx int) {
	name := fld.Key("T").Text()
	full := name
	if parent != "" {
		full = parent + "." + name
	}
	ft := fld.Key("FT").Name()
	if ft == "" {
		ft = "(inherited)"
	}

	// Only print signature fields and a summary line for others.
	if ft == "Sig" {
		filled := "EMPTY"
		if !fld.Key("V").IsNull() {
			filled = "FILLED"
		}
		rect := fld.Key("Rect")
		var r [4]float64
		for j := 0; j < rect.Len() && j < 4; j++ {
			r[j] = rect.Index(j).Float64()
		}
		ptr := fld.GetPtr()
		fmt.Printf("  [SIG %-6s] obj=%d gen=%d name=%q rect=[%.0f %.0f %.0f %.0f] flags(F)=%d Lock=%v\n",
			filled, ptr.GetID(), ptr.GetGen(), full, r[0], r[1], r[2], r[3],
			fld.Key("F").Int64(), !fld.Key("Lock").IsNull())
	} else if idx < 200 {
		fmt.Printf("  [%-4s] %q\n", ft, full)
	}

	kids := fld.Key("Kids")
	for i := 0; i < kids.Len(); i++ {
		dumpField(kids.Index(i), full, i)
	}
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
