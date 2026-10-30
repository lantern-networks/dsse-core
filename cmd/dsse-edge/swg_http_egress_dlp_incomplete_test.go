package main

import (
	"archive/zip"
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDLPUninspectableContainerCannotBypassExplicitBlock(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	xml, err := zw.Create("word/document.xml")
	if err != nil {
		t.Fatal(err)
	}
	// Small compressed upload, but its XML exceeds the extractor's read budget.
	io.WriteString(xml, "<document>"+strings.Repeat(" ", edgeSWGHTTPEgressFileInspectCap)+"123456789018</document>")
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	var form bytes.Buffer
	mw := multipart.NewWriter(&form)
	mw.WriteField("comment", "benign")
	part, err := mw.CreateFormFile("file", "private.docx")
	if err != nil {
		t.Fatal(err)
	}
	part.Write([]byte("corrupt Office document"))
	mw.Close()
	cases := []struct {
		name, contentType string
		body              []byte
	}{
		{"corrupt multipart member", mw.FormDataContentType(), form.Bytes()},
		{"compressed beyond budget", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", archive.Bytes()},
		{"missing boundary", "multipart/form-data", []byte("unparseable")},
		{"malformed multipart", "multipart/form-data; boundary=b", []byte("--b\r\nContent-Disposition: form-data; name=field\r\n\r\nbenign")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, posture := range []struct {
				action            string
				strict, wantBlock bool
			}{
				{"block", true, true}, {"authenticate", true, true}, {"observe", true, false}, {"block", false, false},
			} {
				config, _ := newDLPTestConfig(t)
				config.DLPBlockUninspectableFiles = posture.strict
				req := httptest.NewRequest(http.MethodPost, "https://storage.example.com/upload", bytes.NewReader(tc.body))
				req.Header.Set("Content-Type", tc.contentType)
				hook := installEdgeSWGHTTPEgressDLP(req, config, dlpDecWithInspect("d", "tenant", "", posture.action, "my_number"))
				if hook.blocked() != posture.wantBlock {
					t.Errorf("action=%s strict=%v: blocked=%v want=%v", posture.action, posture.strict, hook.blocked(), posture.wantBlock)
				}
				if hook.skipReason != "extract_error_not_inspected" {
					t.Errorf("incomplete inspection reported as success: %q", hook.skipReason)
				}
				if !posture.wantBlock {
					got, err := io.ReadAll(req.Body)
					if err != nil || !bytes.Equal(got, tc.body) {
						t.Fatal("availability posture changed uploaded bytes")
					}
				}
			}
		})
	}
}
