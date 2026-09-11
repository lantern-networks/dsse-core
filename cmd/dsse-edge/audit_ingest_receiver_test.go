package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/logs"
)

// Audit decoupling: the control plane's receiver persists a shipped record (bearer-authed, known stream) to
// the log stream, rejects a bad token / unknown stream / bad JSON, and is absent when no token is set.
func TestAuditIngestReceiver(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	mux := http.NewServeMux()
	registerAuditIngestReceiver(mux, writer, "ship-secret", nil, nil, nil, true)

	post := func(stream, bearer, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/audit-ingest", strings.NewReader(body))
		if bearer != "" {
			req.Header.Set("authorization", "Bearer "+bearer)
		}
		if stream != "" {
			req.Header.Set("x-audit-stream", stream)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := post("audit.log.jsonl", "ship-secret", `{"event":"x","tenant_id":"t1"}`); code != http.StatusAccepted {
		t.Fatalf("valid ship should be 202, got %d", code)
	}
	if code := post("audit.log.jsonl", "wrong", `{"a":1}`); code != http.StatusUnauthorized {
		t.Fatalf("bad bearer should be 401, got %d", code)
	}
	if code := post("audit.log.jsonl", "", `{"a":1}`); code != http.StatusUnauthorized {
		t.Fatalf("missing bearer should be 401, got %d", code)
	}
	if code := post("secrets.jsonl", "ship-secret", `{"a":1}`); code != http.StatusBadRequest {
		t.Fatalf("unknown stream should be 400, got %d", code)
	}
	if code := post("audit.log.jsonl", "ship-secret", `not-json`); code != http.StatusBadRequest {
		t.Fatalf("invalid JSON should be 400, got %d", code)
	}

	// The persisted record is in the stream.
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 persisted record, got %d", len(rows))
	}

	// No token -> no receiver registered (404).
	bare := http.NewServeMux()
	registerAuditIngestReceiver(bare, writer, "", nil, nil, nil, true)
	req := httptest.NewRequest(http.MethodPost, "/audit-ingest", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	bare.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no token -> receiver absent (404), got %d", rec.Code)
	}
}
