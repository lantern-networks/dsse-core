package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/objectstore"
)

func TestExportRegionCoverageTravelsWithArtifact(t *testing.T) {
	for _, backend := range []string{"logs", "objects"} {
		for _, mode := range []string{"zero", "positive", "failure", "unsupported", "empty", "unfiltered"} {
			t.Run(backend+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				writer, err := logs.NewWriter(dir)
				if err != nil {
					t.Fatal(err)
				}
				if err := writer.Append("access.log.jsonl", map[string]any{"id": "record", "tenant_id": "tenant_lab_001", "timestamp": "2026-05-23T01:10:00Z", "edge_region_id": "region-a"}); err != nil {
					t.Fatal(err)
				}
				var objects adminExportObjectStore = writer
				if backend == "objects" {
					objects, err = objectstore.NewLocalStore(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
				}
				base := hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap())
				counter := &regionCounterFixture{Store: base}
				if mode == "positive" {
					counter.count = 7
				}
				if mode == "failure" {
					counter.err = errors.New("private-count-error")
				}
				var hot hotstore.Store = counter
				if mode == "unsupported" {
					hot = base
				}
				req := adminExportJobRequest{Stream: "access", Format: "ndjson", From: "2026-05-23T01:00:00Z", To: "2026-05-23T02:00:00Z", Filters: map[string]string{"edge_region_id": "region-a"}}
				if mode == "empty" {
					req.Filters["edge_region_id"] = "region-empty"
				}
				if mode == "unfiltered" {
					req.Filters = nil
				}
				now := time.Date(2026, 5, 23, 1, 0, 0, 0, time.UTC)
				jobs := newAdminExportJobStore()
				var completed adminExportJob
				if mode == "positive" {
					queue := newLocalAdminExportTaskQueue()
					worker := localQueuedAdminExportWorker{Queue: queue}
					job, e := worker.Enqueue(context.Background(), adminExportTask{Writer: writer, ObjectStore: objects, HotStore: hot, Store: jobs, Evaluator: testEvaluator(), Request: req, TenantID: "tenant_lab_001", AdminPrincipalID: "admin", SourceIP: "127.0.0.1", Now: now})
					if e != nil {
						t.Fatal(e)
					}
					if !worker.runOne(queue) {
						t.Fatal("queued job not processed")
					}
					completed, _ = jobs.Get(job.ID)
				} else {
					job := jobs.Create(req, "tenant_lab_001", "admin", now)
					completed, err = runAdminExportJob(context.Background(), writer, nil, objects, hot, jobs, testEvaluator(), job, req, "127.0.0.1", now)
				}
				if err != nil {
					t.Fatal(err)
				}
				if completed.Status != "completed" {
					t.Fatal(completed.Status)
				}
				filename, err := adminExportLocalFilename(completed)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := objects.ReadGeneratedFile(filename)
				if err != nil {
					t.Fatal(err)
				}
				checksum := sha256.Sum256(payload)
				if *completed.PayloadChecksum != "sha256:"+hex.EncodeToString(checksum[:]) {
					t.Fatal("checksum excludes manifest")
				}
				gz, err := gzip.NewReader(bytes.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				defer gz.Close()
				body, err := io.ReadAll(gz)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "empty" {
					if len(body) != 0 || completed.RowCount != 0 {
						t.Fatal("empty export gained fabricated rows")
					}
				} else {
					var row map[string]any
					if err := json.Unmarshal(bytes.TrimSpace(body), &row); err != nil || row["id"] != "record" || completed.RowCount != 1 {
						t.Fatalf("log rows changed: %s %v", body, err)
					}
				}
				if mode == "unfiltered" {
					if gz.Comment != "" || completed.Metadata["region_coverage"] != nil {
						t.Fatal("unfiltered export changed")
					}
					return
				}
				var coverage adminExportRegionCoverage
				if err := json.Unmarshal([]byte(gz.Comment), &coverage); err != nil {
					t.Fatal(err)
				}
				if !coverage.RegionFilterApplied || coverage.SnapshotConsistent || coverage.Notice == "" {
					t.Fatal("missing exclusion notice")
				}
				stored, _ := json.Marshal(completed.Metadata["region_coverage"])
				if string(stored) != gz.Comment {
					t.Fatal("job and artifact metadata disagree")
				}
				if mode == "failure" || mode == "unsupported" {
					if coverage.Status != "unavailable" || coverage.UnknownRegionCount != nil {
						t.Fatal("invented count")
					}
				} else {
					if coverage.UnknownRegionCount == nil || *coverage.UnknownRegionCount != counter.count {
						t.Fatal("wrong count")
					}
					if counter.query.TenantID != "tenant_lab_001" || counter.query.From == nil || counter.query.To == nil {
						t.Fatal("lost query scope")
					}
				}
				// The bytes replicated through a download token retain both header and checksum.
				_, token, err := createAdminExportDownloadURL(httptest.NewRequest("GET", "https://console.invalid/", nil), newAdminDownloadTokenStore(), objects, completed, "admin", now)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(token.Payload, payload) {
					t.Fatal("download stripped manifest")
				}
			})
		}
	}
}

func TestRegionalExportRefusesAnObjectStoreWithoutManifestSupport(t *testing.T) {
	s := exportCommentObjectStore{adminExportObjectStore: failingGeneratedObjectStore{}, coverage: &adminExportRegionCoverage{Status: "unavailable"}}
	if _, err := s.WriteGzipJSONLStream("test.gz", func() (map[string]any, bool, error) {
		t.Fatal("unsupported writer consumed rows")
		return nil, false, nil
	}); err == nil {
		t.Fatal("silently omitted coverage")
	}
}
