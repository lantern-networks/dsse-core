package fileextract

import (
	"bytes"
	"mime/multipart"
	"strings"
	"testing"
)

// buildMultipart builds a multipart/form-data body and returns (body, contentType). fileParts map a filename to
// its content-type+bytes; textFields are plain form fields.
func buildMultipart(t *testing.T, textFields map[string]string, fileParts []struct {
	field, filename, contentType string
	data                         []byte
}) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range textFields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("write field: %v", err)
		}
	}
	for _, fp := range fileParts {
		w, err := mw.CreatePart(map[string][]string{
			"Content-Disposition": {`form-data; name="` + fp.field + `"; filename="` + fp.filename + `"`},
			"Content-Type":        {fp.contentType},
		})
		if err != nil {
			t.Fatalf("create part: %v", err)
		}
		w.Write(fp.data)
	}
	mw.Close()
	return buf.String(), mw.FormDataContentType()
}

func TestExtractMultipartWithDocxAndFieldsSkipsBinary(t *testing.T) {
	docx := buildZip(t, map[string]string{
		"word/document.xml": "<w:t>ssn " + syntheticMyNumber + "</w:t>",
	})
	body, ct := buildMultipart(t,
		map[string]string{"comment": "please review card " + syntheticCard},
		[]struct {
			field, filename, contentType string
			data                         []byte
		}{
			{"file", "report.docx", docxContentType, docx},
			{"photo", "img.png", "image/png", []byte("\x89PNG binary 999999999999")},
		},
	)

	text, inspected, err := Extract(ct, []byte(body))
	if err != nil || !inspected {
		t.Fatalf("multipart not inspected: inspected=%v err=%v", inspected, err)
	}
	if !strings.Contains(text, syntheticMyNumber) {
		t.Errorf("docx part text missing; got %q", text)
	}
	if !strings.Contains(text, syntheticCard) {
		t.Errorf("text form field missing; got %q", text)
	}
	if strings.Contains(text, "999999999999") {
		t.Errorf("binary png part was included; got %q", text)
	}
}

func TestExtractDirectOOXML(t *testing.T) {
	docx := buildZip(t, map[string]string{"word/document.xml": "<w:t>" + syntheticMyNumber + "</w:t>"})
	text, inspected, err := Extract(docxContentType, docx)
	if err != nil || !inspected {
		t.Fatalf("direct docx not inspected: %v %v", inspected, err)
	}
	if !strings.Contains(text, syntheticMyNumber) {
		t.Errorf("direct docx text missing; got %q", text)
	}
}

func TestExtractTextLikePassthrough(t *testing.T) {
	text, inspected, err := Extract("application/json", []byte(`{"n":"`+syntheticMyNumber+`"}`))
	if err != nil || !inspected {
		t.Fatalf("json not inspected: %v %v", inspected, err)
	}
	if !strings.Contains(text, syntheticMyNumber) {
		t.Errorf("json passthrough missing text")
	}
}

func TestExtractBinaryNotInspected(t *testing.T) {
	if _, inspected, _ := Extract("image/png", []byte("\x89PNG "+syntheticMyNumber)); inspected {
		t.Errorf("image/png should not be inspected")
	}
	if _, inspected, _ := Extract("application/octet-stream", []byte("blob")); inspected {
		t.Errorf("octet-stream should not be inspected")
	}
}
