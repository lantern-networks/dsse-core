package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestAdminExportRejectsInvalidRequestBeforeWorkerAndAuditsFailure(t *testing.T) {
	for _, req := range []adminExportJobRequest{
		{Stream: "access", Format: "csv", From: "2026-09-14T00:00:00Z", To: "2026-09-14T23:59:59Z"},
		{Stream: "access", Format: "ndjson", From: "2026-09-15T00:00:00Z", To: "2026-09-14T23:59:59Z"},
		{Stream: "access", Format: "ndjson"},
	} {
		writer, err := logs.NewWriter(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		worker := &recordingAdminExportWorker{}
		handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminExportWorker: worker})
		body, _ := json.Marshal(req)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/export-jobs", strings.NewReader(string(body))))
		if rec.Code != 400 || worker.task.Request.Stream != "" {
			t.Fatalf("invalid request reached worker: %d %s", rec.Code, rec.Body.String())
		}
		rows, err := writer.ReadJSONL("audit.log.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, row := range rows {
			if row["target_id"] == "/admin/export-jobs" {
				found = true
				if row["result"] != "error" {
					t.Fatal("invalid export audited as success")
				}
			}
		}
		if !found {
			t.Fatal("failed export request audit absent")
		}
	}
}
func TestAdminExportAllowsInclusiveDayAndEqualInstant(t *testing.T) {
	for _, bounds := range [][2]string{
		{"2026-09-13T15:00:00Z", "2026-09-14T14:59:59.999999999Z"},
		{"2026-09-14T00:00:00Z", "2026-09-14T00:00:00Z"},
	} {
		if err := validateAdminExportJobRequest(adminExportJobRequest{Stream: "access", Format: "ndjson", From: bounds[0], To: bounds[1]}); err != nil {
			t.Fatal(err)
		}
	}
}
