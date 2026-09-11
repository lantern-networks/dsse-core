package fileextract

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// buildMinimalPDF assembles a tiny single-page PDF whose content stream shows `text` (a Tj operator in a
// standard Helvetica font), computing the xref offsets so dslipak/pdf can parse it. Synthetic; no real file.
func buildMinimalPDF(text string) []byte {
	var b bytes.Buffer
	var offsets []int
	obj := func(s string) {
		offsets = append(offsets, b.Len())
		b.WriteString(s)
	}
	b.WriteString("%PDF-1.4\n")
	obj("1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n")
	obj("2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n")
	obj("3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>\nendobj\n")
	content := "BT /F1 12 Tf 72 700 Td (" + text + ") Tj ET"
	obj(fmt.Sprintf("4 0 obj\n<</Length %d>>\nstream\n%s\nendstream\nendobj\n", len(content), content))
	obj("5 0 obj\n<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>\nendobj\n")
	xrefOff := b.Len()
	b.WriteString("xref\n0 6\n0000000000 65535 f \n")
	for _, off := range offsets {
		b.WriteString(fmt.Sprintf("%010d 00000 n \n", off))
	}
	b.WriteString(fmt.Sprintf("trailer\n<</Size 6/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n", xrefOff))
	return b.Bytes()
}

func TestExtractPDFText(t *testing.T) {
	pdf := buildMinimalPDF(syntheticMyNumber)
	text, err := ExtractPDFText(pdf)
	if err != nil {
		t.Fatalf("extract pdf: %v", err)
	}
	if !strings.Contains(strings.ReplaceAll(text, " ", ""), syntheticMyNumber) {
		t.Errorf("pdf text missing the My Number; got %q", text)
	}
}

func TestExtractPDFTextMalformedNoPanic(t *testing.T) {
	// A non-PDF / corrupt input must not panic; it returns an error.
	if _, err := ExtractPDFText([]byte("this is not a pdf")); err == nil {
		t.Errorf("expected an error for non-PDF input")
	}
}

func TestExtractRoutesPDF(t *testing.T) {
	pdf := buildMinimalPDF(syntheticMyNumber)
	text, inspected, err := Extract(pdfContentType, pdf)
	if err != nil || !inspected {
		t.Fatalf("pdf not inspected via Extract: inspected=%v err=%v", inspected, err)
	}
	if !strings.Contains(strings.ReplaceAll(text, " ", ""), syntheticMyNumber) {
		t.Errorf("Extract(pdf) missing text; got %q", text)
	}
}
