package logs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// tenant isolation: partitioned logs are physically separated per tenant on disk; ReadJSONLTenant
// returns ONLY that tenant's rows, ReadJSONL aggregates, and a tenant's partition file never contains
// another tenant's rows.
func TestTenantPartitionedLogsIsolation(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	w.SetTenantPartitionedFiles("audit.log.jsonl")

	mustAppend := func(tenant, id string) {
		if err := w.Append("audit.log.jsonl", map[string]any{"id": id, "tenant_id": tenant}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	mustAppend("tenant_a", "a1")
	mustAppend("tenant_b", "b1")
	mustAppend("tenant_a", "a2")

	a, _ := w.ReadJSONLTenant("tenant_a", "audit.log.jsonl")
	if len(a) != 2 {
		t.Fatalf("tenant_a partition: want 2 rows, got %d", len(a))
	}
	for _, row := range a {
		if row["tenant_id"] != "tenant_a" {
			t.Fatalf("ISOLATION VIOLATION: tenant_a partition contains %v", row)
		}
	}
	b, _ := w.ReadJSONLTenant("tenant_b", "audit.log.jsonl")
	if len(b) != 1 || b[0]["tenant_id"] != "tenant_b" {
		t.Fatalf("tenant_b partition: want 1 tenant_b row, got %v", b)
	}
	// Aggregate read sees all.
	all, _ := w.ReadJSONL("audit.log.jsonl")
	if len(all) != 3 {
		t.Fatalf("aggregate: want 3 rows, got %d", len(all))
	}
	// Physical separation on disk.
	if _, err := os.Stat(filepath.Join(dir, "tenants", "tenant_a", "audit.log.jsonl")); err != nil {
		t.Fatalf("expected tenant_a partition file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tenants", "tenant_b", "audit.log.jsonl")); err != nil {
		t.Fatalf("expected tenant_b partition file: %v", err)
	}
	// The root (co-mingled) file must NOT be written when partitioning is on.
	if _, err := os.Stat(filepath.Join(dir, "audit.log.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("co-mingled root audit.log.jsonl must not exist when partitioned (err=%v)", err)
	}
}

func TestWriterAppendHookReceivesEncodedRowAfterWrite(t *testing.T) {
	writer, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}

	var gotFilename string
	var gotEncoded []byte
	writer.SetAppendHook(func(filename string, encoded []byte) error {
		gotFilename = filename
		gotEncoded = append([]byte(nil), encoded...)
		return nil
	})

	if err := writer.Append("access.log.jsonl", map[string]any{
		"id":        "alog_hook_001",
		"tenant_id": "tenant_lab_001",
		"decision":  "allow",
	}); err != nil {
		t.Fatalf("Append returned error: %v", err)
	}
	if gotFilename != "access.log.jsonl" {
		t.Fatalf("hook filename = %q, want access.log.jsonl", gotFilename)
	}
	var row map[string]any
	if err := json.Unmarshal(gotEncoded, &row); err != nil {
		t.Fatalf("hook encoded row is not JSON: %v", err)
	}
	if row["id"] != "alog_hook_001" || row["tenant_id"] != "tenant_lab_001" {
		t.Fatalf("hook row = %#v", row)
	}

	rows, err := writer.ReadJSONL("access.log.jsonl")
	if err != nil {
		t.Fatalf("ReadJSONL returned error: %v", err)
	}
	if len(rows) != 1 || rows[0]["id"] != "alog_hook_001" {
		t.Fatalf("rows = %#v", rows)
	}
}

func TestWriterAppendHookCanBeCleared(t *testing.T) {
	writer, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}

	called := 0
	writer.SetAppendHook(func(filename string, encoded []byte) error {
		called++
		return nil
	})
	writer.SetAppendHook(nil)

	if err := writer.Append("audit.log.jsonl", map[string]any{"id": "audit_hook_001"}); err != nil {
		t.Fatalf("Append returned error: %v", err)
	}
	if called != 0 {
		t.Fatalf("append hook called %d times after clear", called)
	}
}

func TestWriterRejectsUnsafeRelativePaths(t *testing.T) {
	writer, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	for name, run := range map[string]func() error{
		"append traversal": func() error {
			return writer.Append("../outside.log.jsonl", map[string]any{"id": "row_001"})
		},
		"read traversal": func() error {
			_, err := writer.ReadJSONL("../outside.log.jsonl")
			return err
		},
		"write generated traversal": func() error {
			_, err := writer.WriteGzipJSONL("../outside.ndjson.gz", []map[string]any{{"id": "row_001"}})
			return err
		},
		"read generated absolute": func() error {
			_, err := writer.ReadGeneratedFile("/tmp/outside.ndjson.gz")
			return err
		},
		"list generated traversal": func() error {
			_, err := writer.ListGeneratedFiles("../outside", ".gz", 10)
			return err
		},
	} {
		err := run()
		if err == nil || !strings.Contains(err.Error(), "outside log dir") {
			t.Fatalf("%s error = %v, want outside log dir", name, err)
		}
	}
}

func TestWriterListGeneratedFilesFiltersSuffix(t *testing.T) {
	writer, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	if _, err := writer.WriteGzipJSONL("domain-events/tenant/domain/2026/05/24/event_001.ndjson.gz", []map[string]any{{"id": "event_001"}}); err != nil {
		t.Fatalf("WriteGzipJSONL object returned error: %v", err)
	}
	if _, err := writer.WriteGzipJSONL("domain-events/tenant/domain/2026/05/24/event_001.manifest.ndjson.gz", []map[string]any{{"id": "manifest_001"}}); err != nil {
		t.Fatalf("WriteGzipJSONL manifest returned error: %v", err)
	}

	files, err := writer.ListGeneratedFiles("domain-events/", ".manifest.ndjson.gz", 10)
	if err != nil {
		t.Fatalf("ListGeneratedFiles returned error: %v", err)
	}
	if len(files) != 1 || files[0] != "domain-events/tenant/domain/2026/05/24/event_001.manifest.ndjson.gz" {
		t.Fatalf("files = %#v", files)
	}
}

func TestWriterWriteGzipJSONLStreamCleansPartialFileOnError(t *testing.T) {
	writer, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	filename := "exports/tenant_lab_001/partial.ndjson.gz"
	_, err = writer.WriteGzipJSONLStream(filename, func() (map[string]any, bool, error) {
		return nil, false, fmt.Errorf("boom")
	})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("WriteGzipJSONLStream error = %v, want boom", err)
	}
	if _, err := writer.ReadGeneratedFile(filename); err == nil {
		t.Fatalf("ReadGeneratedFile returned nil error for failed partial write")
	}
}

func TestWriterGeneratedFileReadWaitsForSameFileWrite(t *testing.T) {
	writer, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	filename := "exports/tenant_lab_001/blocking.ndjson.gz"
	started := make(chan struct{})
	release := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		index := 0
		_, err := writer.WriteGzipJSONLStream(filename, func() (map[string]any, bool, error) {
			if index > 0 {
				return nil, false, nil
			}
			index++
			close(started)
			<-release
			return map[string]any{"id": "row_001"}, true, nil
		})
		writeDone <- err
	}()
	<-started

	readDone := make(chan error, 1)
	go func() {
		_, err := writer.ReadGeneratedFile(filename)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		t.Fatalf("ReadGeneratedFile returned before same-file write completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-writeDone; err != nil {
		t.Fatalf("WriteGzipJSONLStream returned error: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("ReadGeneratedFile returned error after write completed: %v", err)
	}
}

func TestWriterGeneratedFileConcurrentDifferentFiles(t *testing.T) {
	writer, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			filename := fmt.Sprintf("exports/tenant_lab_001/file_%02d.ndjson.gz", i)
			_, err := writer.WriteGzipJSONL(filename, []map[string]any{{"id": fmt.Sprintf("row_%02d", i)}})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent WriteGzipJSONL returned error: %v", err)
		}
	}
	files, err := writer.ListGeneratedFiles("exports/tenant_lab_001", ".ndjson.gz", 20)
	if err != nil {
		t.Fatalf("ListGeneratedFiles returned error: %v", err)
	}
	if len(files) != 8 {
		t.Fatalf("files = %#v, want 8 files", files)
	}
}
