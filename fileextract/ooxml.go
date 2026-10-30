// Package fileextract extracts plain text from uploaded files so the DLP engine (oss/dlp) can inspect their
// contents, not just plain-text request bodies. It is pure Go and dependency-free: Office OOXML (docx/xlsx/
// pptx) are ZIP+XML and are handled with the standard library only. Other formats (PDF, images) are out of
// scope here — PDF needs a third-party library and is kept separate so this package stays stdlib-only and
// OSS-core-clean. See docs/dlp_minimal_design.md.
//
// Structured files cannot be stream-extracted (a ZIP's central directory is at the end), so callers buffer the
// file (with a size cap) and pass the bytes here; extraction itself is also cap-bounded to stay safe against
// decompression bombs.
package fileextract

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// DefaultMaxExtractedBytes bounds how much text a single file may yield, so a decompression bomb cannot exhaust
// memory. Extraction stops once this many bytes have been collected.
const DefaultMaxExtractedBytes = 32 << 20 // 32 MiB

// OOXML content types (the file part's declared MIME type) and extensions.
const (
	docxContentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	xlsxContentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	pptxContentType = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
)

// IsOOXML reports whether a file (by declared content type and/or filename) is an OOXML Office document.
func IsOOXML(filename, contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case docxContentType, xlsxContentType, pptxContentType:
		return true
	}
	name := strings.ToLower(strings.TrimSpace(filename))
	return strings.HasSuffix(name, ".docx") ||
		strings.HasSuffix(name, ".xlsx") ||
		strings.HasSuffix(name, ".pptx")
}

// ExtractText returns the extracted plain text for a supported file. handled=false means the format is not one
// this package extracts (the caller should skip it or handle plain text itself); err is only for a file that
// IS a supported format but could not be read (e.g. a corrupt archive).
func ExtractText(filename, contentType string, data []byte) (text string, handled bool, err error) {
	if IsOOXML(filename, contentType) {
		t, e := ExtractOOXMLText(data)
		return t, true, e
	}
	return "", false, nil
}

// ExtractOOXMLText unzips an OOXML document and returns the concatenated text of every XML part (each text
// node on its own line). It is format-agnostic across docx/xlsx/pptx: the payload text of Word runs (<w:t>),
// Excel shared strings and cell values (<t>/<v>), and PowerPoint runs (<a:t>) all surface as XML character
// data. Pure standard library.
func ExtractOOXMLText(data []byte) (string, error) {
	return extractOOXMLText(data, DefaultMaxExtractedBytes)
}

func extractOOXMLText(data []byte, maxBytes int) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	// Keep the decompression bound, but report incomplete inspection to callers.
	// A small compressed archive may hide text after a large whitespace prefix.
	readBudget := int64(maxBytes)
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			continue
		}
		if f.UncompressedSize64 > uint64(readBudget) {
			return sb.String(), ErrExtractionLimit
		}
		rc, err := f.Open()
		if err != nil {
			return sb.String(), fmt.Errorf("cannot open Office XML member: %w", err)
		}
		lr := &io.LimitedReader{R: rc, N: readBudget + 1}
		err = appendXMLText(&sb, lr, maxBytes)
		consumed := readBudget + 1 - lr.N
		closeErr := rc.Close()
		if consumed > readBudget {
			return sb.String(), ErrExtractionLimit
		}
		readBudget -= consumed
		if err != nil {
			return sb.String(), fmt.Errorf("cannot inspect Office XML member: %w", err)
		}
		if closeErr != nil {
			return sb.String(), closeErr
		}
	}
	return sb.String(), nil
}

// appendXMLText never reports malformed or truncated XML as successfully inspected.
func appendXMLText(sb *strings.Builder, r io.Reader, maxBytes int) error {
	dec := xml.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		cd, ok := tok.(xml.CharData)
		if !ok {
			continue
		}
		t := strings.TrimSpace(string(cd))
		if t == "" {
			continue
		}
		if len(t)+1 > maxBytes-sb.Len() {
			return ErrExtractionLimit
		}
		sb.WriteString(t)
		sb.WriteByte('\n')
	}
}
