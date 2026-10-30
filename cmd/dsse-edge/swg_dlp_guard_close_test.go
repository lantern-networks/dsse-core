package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type dlpCloseTrackedBody struct {
	io.Reader
	closed int
}

func (b *dlpCloseTrackedBody) Close() error {
	b.closed++
	return nil
}

func TestDLPRequestCancellationClosesGuardAndOriginalBody(t *testing.T) {
	config, _ := newDLPTestConfig(t)
	body := &dlpCloseTrackedBody{Reader: strings.NewReader(strings.Repeat("benign text ", 5000))}
	req := httptest.NewRequest(http.MethodPost, "https://upload.invalid/body", body)
	req.Header.Set("Content-Type", "text/plain")
	installEdgeSWGHTTPEgressDLP(req, config, dlpDecWithInspect("decision", "tenant", "app", "block", "email"))
	if err := req.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := req.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if body.closed != 1 {
		t.Fatalf("request abort closed original body %d times", body.closed)
	}
	var next [1]byte
	if n, err := req.Body.Read(next[:]); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("closed guard still produced upload data: n=%d err=%v", n, err)
	}
}
