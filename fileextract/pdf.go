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
// nothing (OCR is out of scope). Encrypted or malformed PDFs return an error (the caller fails open and
// forwards uninspected). The extractor libraries can panic on adversarial input, so it is recover-guarded —
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
	_, _ = io.Copy(&sb, io.LimitReader(tr, DefaultMaxExtractedBytes)) // partial text on a copy error is fine
	return sb.String(), nil
}
