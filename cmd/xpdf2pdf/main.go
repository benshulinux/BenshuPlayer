// Command xpdf2pdf is the standalone BenshuPlayer .xpdf ebook decryptor.
// It is deliberately network-free: given an .xpdf file and the course's
// 32-hex ebook key (plaintext), it writes the PDF.
//
// The key comes from `BenshuPlayer xpdf`/`course` (gist cache or server):
//
//	xpdf2pdf -file book.xpdf -key cafd9a4acf8a8490ea07e8253c549090 [-out book.pdf]
//
// This binary contains no vendor code and no network access — it is the
// interoperability tool for owners of purchased content.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"benshuplayer/internal/xpdf"
)

func main() {
	fs := flag.NewFlagSet("xpdf2pdf", flag.ExitOnError)
	file := fs.String("file", "", "input .xpdf file")
	key := fs.String("key", "", "32-hex course key (ebookKey plaintext)")
	out := fs.String("out", "", "output .pdf path (default: input with .pdf suffix)")
	fs.Parse(os.Args[1:])

	if *file == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "usage: xpdf2pdf -file <book.xpdf> -key <32hex> [-out <book.pdf>]")
		os.Exit(2)
	}
	k := strings.TrimSpace(strings.ToLower(*key))
	if len(k) != 32 {
		fmt.Fprintf(os.Stderr, "xpdf2pdf: -key must be 32 hex chars, got %d\n", len(k))
		os.Exit(2)
	}
	for _, c := range k {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			fmt.Fprintf(os.Stderr, "xpdf2pdf: -key must be hex\n")
			os.Exit(2)
		}
	}

	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xpdf2pdf: %v\n", err)
		os.Exit(1)
	}
	h, err := xpdf.ParseHeader(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xpdf2pdf: %v\n", err)
		os.Exit(1)
	}
	pt, err := xpdf.DecryptBody(xpdf.FileKey(k), raw[xpdf.HeaderLen:], h)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xpdf2pdf: decrypt: %v\n", err)
		os.Exit(1)
	}

	outPath := *out
	if outPath == "" {
		outPath = strings.TrimSuffix(*file, filepath.Ext(*file)) + ".pdf"
	}
	if err := os.WriteFile(outPath, pt, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "xpdf2pdf: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("xpdf -> pdf: %s (%d bytes, course %d)\n", outPath, len(pt), h.CourseID)
}
