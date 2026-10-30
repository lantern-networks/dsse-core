package fileextract

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/dslipak/pdf"
)

const pdfContentType = "application/pdf"

// IsPDF reports whether a file (by content type and/or filename) is a PDF.
func IsPDF(filename, contentType string) bool {
	if strings.ToLower(strings.TrimSpace(firstToken(contentType))) == pdfContentType {
		return true
	}
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(filename)), ".pdf")
}

// ExtractPDFText extracts the text layer of a PDF using dslipak/pdf (pure Go, BSD-licensed, rsc.io/pdf
// lineage — no CGo, no external process). Cap-bounded. A scanned/image PDF has no text layer and yields
// nothing (OCR is out of scope). Encrypted, malformed or over-budget PDFs return an error so the
// caller can apply its configured uninspectable-file policy. The extractor libraries can panic on adversarial input, so it is recover-guarded —
// a bad PDF must never crash the Edge.
func ExtractPDFText(data []byte) (text string, err error) {
	defer func() {
		if r := recover(); r != nil {
			text, err = "", fmt.Errorf("pdf extract recovered from panic: %v", r)
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	tr, err := r.GetPlainText()
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	n, err := io.Copy(&sb, io.LimitReader(tr, DefaultMaxExtractedBytes+1))
	if err != nil {
		return "", err
	}
	if n > DefaultMaxExtractedBytes {
		return "", ErrExtractionLimit
	}
	return sb.String(), nil
}
