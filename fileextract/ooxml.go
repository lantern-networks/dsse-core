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
	// readBudget bounds DECOMPRESSED bytes read from the archive, not just produced text. Capping only the
	// collected text left the read side unbounded: a zip bomb whose XML inflates to whitespace (or markup)
	// never grows sb, so the cap never tripped and decompression burned unbounded CPU + per-token memory.
	// The budget is shared across parts; when it runs out the XML decoder sees EOF and extraction stops with
	// whatever text was collected (the same take-what-we-have semantics as the text cap).
	readBudget := int64(maxBytes)
	for _, f := range zr.File {
		if sb.Len() >= maxBytes || readBudget <= 0 {
			break
		}
		if !strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			continue // media, binary parts, relationships — no scannable text
		}
		rc, err := f.Open()
		if err != nil {
			continue // skip an unreadable part rather than failing the whole file
		}
		lr := &io.LimitedReader{R: rc, N: readBudget}
		appendXMLText(&sb, lr, maxBytes)
		readBudget = lr.N
		rc.Close()
	}
	return sb.String(), nil
}

// appendXMLText writes each non-empty XML text node from r to sb (one per line), stopping at the byte cap.
func appendXMLText(sb *strings.Builder, r io.Reader, maxBytes int) {
	dec := xml.NewDecoder(r)
	for {
		remaining := maxBytes - sb.Len()
		if remaining <= 0 {
			return
		}
		tok, err := dec.Token()
		if err != nil {
			return // EOF or malformed — take what we have
		}
		cd, ok := tok.(xml.CharData)
		if !ok {
			continue
		}
		t := strings.TrimSpace(string(cd))
		if t == "" {
			continue
		}
		if len(t) > remaining { // truncate a single oversize node so one node can't blow the cap
			t = t[:remaining]
		}
		sb.WriteString(t)
		sb.WriteByte('\n')
	}
}
