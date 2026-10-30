package fileextract

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strings"
)

// ErrExtractionLimit means only a prefix could be inspected. Callers must apply
// their uninspectable-file policy, rather than treating that prefix as a clean file.
var ErrExtractionLimit = errors.New("file text extraction exceeds inspection budget")

// Extract returns the scannable plain text of an upload body for DLP inspection, and whether it inspected
// anything. For multipart/form-data it walks the parts — extracting recognized file parts (Office now, PDF via
// F3) and including text parts / plain form fields verbatim, skipping non-text binary parts. For a direct
// Office/PDF body it extracts the document text. For a plain text-like body it returns the body as-is.
// inspected=false means the body is a binary type this package does not inspect (the caller skips + logs it).
//
// Structured files are not streamable, so the caller passes a buffered (size-capped) body; extraction is also
// cap-bounded internally.
func Extract(contentType string, body []byte) (text string, inspected bool, err error) {
	mt, params, perr := mime.ParseMediaType(contentType)
	if perr != nil {
		mt = strings.ToLower(strings.TrimSpace(firstToken(contentType)))
	}
	mt = strings.ToLower(strings.TrimSpace(mt))
	switch {
	case strings.HasPrefix(mt, "multipart/"):
		return extractMultipart(body, params["boundary"])
	case IsOOXML("", contentType):
		t, e := ExtractOOXMLText(body)
		return t, true, e
	case IsPDF("", contentType):
		t, e := ExtractPDFText(body)
		return t, true, e
	case isTextLike(mt):
		return string(body), true, nil
	default:
		return "", false, nil
	}
}

// extractMultipart concatenates the scannable text of every part: recognized file parts are extracted, text
// parts and plain form fields are included verbatim, binary parts are skipped.
func extractMultipart(body []byte, boundary string) (string, bool, error) {
	if strings.TrimSpace(boundary) == "" {
		return "", false, errors.New("multipart boundary is missing")
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var sb strings.Builder
	inspected := false
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", inspected, errors.New("malformed multipart upload")
		}
		partCT, filename := p.Header.Get("Content-Type"), p.FileName()
		data, err := io.ReadAll(io.LimitReader(p, DefaultMaxExtractedBytes+1))
		// Do not drain an over-budget part: the whole buffered upload is rejected
		// for inspection, and no partially inspected text is called successful.
		if err != nil {
			return "", inspected, errors.New("cannot read multipart member")
		}
		if len(data) > DefaultMaxExtractedBytes {
			return "", inspected, ErrExtractionLimit
		}
		if err := p.Close(); err != nil {
			return "", inspected, errors.New("cannot close multipart member")
		}
		var text string
		switch {
		case IsOOXML(filename, partCT):
			text, err = ExtractOOXMLText(data)
		case IsPDF(filename, partCT):
			text, err = ExtractPDFText(data)
		case partCT == "" || isTextLike(strings.ToLower(firstToken(partCT))):
			text = string(data)
		default:
			continue // non-text binary formats remain outside extraction support
		}
		if err != nil {
			return "", inspected, fmt.Errorf("multipart member could not be inspected: %w", err)
		}
		inspected = true
		if len(text) == 0 {
			continue
		}
		if len(text)+1 > DefaultMaxExtractedBytes-sb.Len() {
			return "", inspected, ErrExtractionLimit
		}
		sb.WriteString(text)
		sb.WriteByte('\n')
	}
	return sb.String(), inspected, nil
}

// isTextLike reports whether a media type carries scannable text (mirrors the text gate; kept local so
// fileextract has no dependency on the detection engine).
func isTextLike(mt string) bool {
	switch {
	case strings.HasPrefix(mt, "text/"),
		mt == "application/json",
		strings.HasSuffix(mt, "+json"),
		mt == "application/x-www-form-urlencoded",
		mt == "application/xml",
		strings.HasSuffix(mt, "+xml"),
		mt == "application/csv",
		mt == "application/x-ndjson",
		mt == "application/graphql":
		return true
	default:
		return false
	}
}

// firstToken returns the media type before any ';' parameters.
func firstToken(contentType string) string {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		return contentType[:i]
	}
	return contentType
}
