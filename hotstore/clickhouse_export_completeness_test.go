package hotstore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClickHouseExportReportsRowsBeyondLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sql, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(sql), "count() OVER ()") {
			t.Error("export does not count the whole matching set")
		}
		if r.URL.Query().Get("param_lim") != "1" || r.URL.Query().Get("param_tenant") != "acme" {
			t.Error("export scope missing")
		}
		fmt.Fprintln(w, `{"raw":"{\"event_id\":\"a\"}","total_matches":"3"}`)
	}))
	defer server.Close()
	n := 0
	result, err := NewClickHouseStore(server.URL, "", "", "dsse", "events").ExportRows(context.Background(), SearchQuery{TenantID: "acme", Stream: "audit", Limit: 1}, func(map[string]any) error { n++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || result.RowsExported != 1 || result.TotalMatches != 3 {
		t.Fatalf("limited export falsely complete: %+v, yielded %d", result, n)
	}
}

func TestClickHouseExportRejectsIncompleteHTTPBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		fmt.Fprintln(w, `{"raw":"{\"event_id\":\"a\"}","total_matches":"1"}`)
	}))
	defer server.Close()
	n := 0
	_, err := NewClickHouseStore(server.URL, "", "", "dsse", "events").ExportRows(context.Background(), SearchQuery{TenantID: "acme", Stream: "audit", Limit: 1}, func(map[string]any) error { n++; return nil })
	if err == nil || n != 0 {
		t.Fatalf("incomplete body accepted: err=%v yielded=%d", err, n)
	}
}

func TestClickHouseExportCountMustBeValidAndConsistent(t *testing.T) {
	for _, body := range []string{
		`{"raw":"{}"}`,
		`{"raw":"{}","total_matches":"0"}`,
		`{"raw":"{}","total_matches":"-1"}`,
		`{"raw":"{}","total_matches":"999999999999999999999999"}`,
		"{\"raw\":\"{}\",\"total_matches\":2}\n{\"raw\":\"{}\",\"total_matches\":3}\n",
		"{\"raw\":\"{}\",\"total_matches\":1}\n{\"raw\":\"{}\",\"total_matches\":1}\n",
	} {
		if _, _, err := parseClickHouseExportRows([]byte(body)); err == nil {
			t.Fatalf("invalid export accepted: %s", body)
		}
	}
	rows, total, err := parseClickHouseExportRows(nil)
	if err != nil || len(rows) != 0 || total != 0 {
		t.Fatalf("empty export: rows=%d total=%d err=%v", len(rows), total, err)
	}
}
