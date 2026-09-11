package fileextract

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"strings"
)

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
		return "", false, nil
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var sb strings.Builder
	inspected := false
	for {
		if sb.Len() >= DefaultMaxExtractedBytes {
			break
		}
		p, err := mr.NextPart()
		if err != nil {
			break // EOF or malformed — take what we have
		}
		partCT := p.Header.Get("Content-Type")
		filename := p.FileName()
		data, _ := io.ReadAll(io.LimitReader(p, DefaultMaxExtractedBytes))
		p.Close()
		switch {
		case IsOOXML(filename, partCT):
			if t, e := ExtractOOXMLText(data); e == nil && t != "" {
				sb.WriteString(t)
				sb.WriteByte('\n')
				inspected = true
			}
		case IsPDF(filename, partCT):
			if t, e := ExtractPDFText(data); e == nil && t != "" {
				sb.WriteString(t)
				sb.WriteByte('\n')
				inspected = true
			}
		case partCT == "" || isTextLike(strings.ToLower(firstToken(partCT))):
			// a text part or a plain form field (form fields carry no Content-Type) → scannable text
			sb.Write(data)
			sb.WriteByte('\n')
			inspected = true
		default:
			// binary non-file part → skip
		}
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
