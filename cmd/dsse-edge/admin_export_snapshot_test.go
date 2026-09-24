package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/objectstore"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// HTTP responses and audit builders encode jobs after the Store lock is released.
// Keep every earlier response stable while the worker advances the same job.
func TestAdminExportJobResponsesRemainStable(t *testing.T) {
	s := newAdminExportJobStore()
	now := time.Now()
	created := s.Create(adminExportJobRequest{Stream: "access", Filters: map[string]string{"host": "example.invalid"}}, "tenant-a", "admin-a", now)
	type snapshot struct {
		job adminExportJob
		raw string
	}
	snapshots := []snapshot{}
	remember := func(job adminExportJob) {
		b, err := json.Marshal(job)
		if err != nil {
			t.Fatal(err)
		}
		snapshots = append(snapshots, snapshot{job, string(b)})
	}
	check := func() {
		t.Helper()
		for _, v := range snapshots {
			b, err := json.Marshal(v.job)
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != v.raw {
				t.Fatalf("earlier %s response changed after worker update", v.job.Status)
			}
		}
	}
	remember(created)
	running, err := s.MarkRunning(created.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	check()
	remember(running)
	read, _ := s.Get(created.ID)
	remember(read)
	remember(s.List("tenant-a")[0])
	progress, err := s.MarkProgress(created.ID, 1, "exporting", now)
	if err != nil {
		t.Fatal(err)
	}
	check()
	remember(progress)
	cancelled, err := s.MarkCancelled(created.ID, "tenant-a", "admin-a", "test", now)
	if err != nil {
		t.Fatal(err)
	}
	check()
	cancelled.Metadata["progress_phase"] = "caller mutation"
	cancelled.Filters["host"] = "changed"
	final, _ := s.Get(created.ID)
	if final.Metadata["progress_phase"] != "cancelled" || final.Filters["host"] != "example.invalid" {
		t.Fatal("response mutation changed stored job")
	}
}

func TestAdminExportJobConcurrentResponseEncoding(t *testing.T) {
	s := newAdminExportJobStore()
	now := time.Now()
	j := s.Create(adminExportJobRequest{Stream: "access"}, "tenant-a", "admin-a", now)
	if _, err := s.MarkRunning(j.ID, now); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			if _, err := s.MarkProgress(j.ID, i, "exporting", now); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 0; i < 300; i++ {
		jobs := s.List("tenant-a")
		if _, err := json.Marshal(jobs); err != nil {
			t.Fatal(err)
		}
		job, _ := s.Get(j.ID)
		if _, err := json.Marshal(job); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

// Stop after one encoded row, below the worker's 1,000-row progress interval.
type cancelAfterFirstExportRow struct {
	adminExportObjectStore
	cancel func()
}

func (s cancelAfterFirstExportRow) WriteGzipJSONLStream(filename string, next func() (map[string]any, bool, error)) (string, error) {
	calls := 0
	return s.adminExportObjectStore.WriteGzipJSONLStream(filename, func() (map[string]any, bool, error) {
		calls++
		if calls == 2 {
			s.cancel()
		}
		return next()
	})
}
func TestAdminExportJobCancellationBeforeFinalRowCleansFile(t *testing.T) {
	for _, backend := range []string{"logs", "objectstore"} {
		t.Run(backend, func(t *testing.T) {
			dir := t.TempDir()
			writer, err := logs.NewWriter(dir)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			for i := 0; i < 2; i++ {
				if err := writer.Append("access.log.jsonl", map[string]any{"id": fmt.Sprint(i), "tenant_id": "tenant-a", "timestamp": now.Format(time.RFC3339)}); err != nil {
					t.Fatal(err)
				}
			}
			var output adminExportObjectStore = writer
			if backend == "objectstore" {
				output, err = objectstore.NewLocalStore(dir)
				if err != nil {
					t.Fatal(err)
				}
			}
			jobs := newAdminExportJobStore()
			request := adminExportJobRequest{Stream: "access", From: now.Add(-time.Hour).Format(time.RFC3339), To: now.Add(time.Hour).Format(time.RFC3339)}
			job := jobs.Create(request, "tenant-a", "admin-a", now)
			output = cancelAfterFirstExportRow{output, func() {
				if _, err := jobs.MarkCancelled(job.ID, "tenant-a", "admin-a", "test", now); err != nil {
					t.Fatal(err)
				}
			}}
			final, err := runAdminExportJob(context.Background(), writer, nil, output, hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()), jobs, testEvaluator(), job, request, "127.0.0.1", now)
			if err != nil {
				t.Fatalf("cancelled job returned error: %v", err)
			}
			if final.Status != "cancelled" {
				t.Fatalf("status=%s", final.Status)
			}
			name, err := adminExportLocalFilename(job)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
				t.Fatalf("cancelled export file remains: %v", err)
			}
		})
	}
}
