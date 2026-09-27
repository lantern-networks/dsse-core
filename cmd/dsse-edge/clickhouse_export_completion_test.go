package main

import (
	"context"
	"fmt"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/objectstore"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClickHouseExportJobMarksCappedOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		if strings.Contains(string(query), "count() OVER ()") {
			fmt.Fprintln(w, `{"raw":"{\"tenant_id\":\"tenant_lab_001\",\"id\":\"record\"}","total_matches":"3"}`)
		} else {
			fmt.Fprintln(w, "0")
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := objectstore.NewLocalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	jobs := newAdminExportJobStore()
	now := time.Now().UTC()
	req := adminExportJobRequest{Stream: "audit", Format: "ndjson", From: now.Add(-time.Hour).Format(time.RFC3339), To: now.Format(time.RFC3339), Limit: 1}
	job := jobs.Create(req, "tenant_lab_001", "admin", now)
	hot := hotstore.NewClickHouseStore(server.URL, "", "", "dsse", "events")
	completed, err := runAdminExportJob(context.Background(), writer, nil, objects, hot, jobs, testEvaluator(), job, req, "127.0.0.1", now)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != "completed" || completed.RowCount != 1 || completed.Metadata["truncated"] != true || fmt.Sprint(completed.Metadata["total_matches"]) != "3" {
		t.Fatalf("capped export not identified: %+v", completed)
	}
}
