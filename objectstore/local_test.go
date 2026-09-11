package objectstore

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalStoreWriteReadGzipJSONL(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	checksum, err := store.WriteGzipJSONL("exports/tenant_lab_001/2026/05/23/export_001.ndjson.gz", []map[string]any{
		{"id": "row_001", "tenant_id": "tenant_lab_001"},
	})
	if err != nil {
		t.Fatalf("WriteGzipJSONL returned error: %v", err)
	}
	if !strings.HasPrefix(checksum, "sha256:") {
		t.Fatalf("checksum = %q", checksum)
	}
	data, err := store.ReadGeneratedFile("exports/tenant_lab_001/2026/05/23/export_001.ndjson.gz")
	if err != nil {
		t.Fatalf("ReadGeneratedFile returned error: %v", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll returned error: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if !strings.Contains(string(decoded), `"row_001"`) {
		t.Fatalf("decoded = %s", decoded)
	}
}

func TestLocalStoreWriteGzipJSONLStream(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	rows := []map[string]any{
		{"id": "row_001", "tenant_id": "tenant_lab_001"},
		{"id": "row_002", "tenant_id": "tenant_lab_001"},
	}
	index := 0
	checksum, err := store.WriteGzipJSONLStream("exports/tenant_lab_001/2026/05/23/export_stream.ndjson.gz", func() (map[string]any, bool, error) {
		if index >= len(rows) {
			return nil, false, nil
		}
		row := rows[index]
		index++
		return row, true, nil
	})
	if err != nil {
		t.Fatalf("WriteGzipJSONLStream returned error: %v", err)
	}
	if !strings.HasPrefix(checksum, "sha256:") {
		t.Fatalf("checksum = %q", checksum)
	}
	data, err := store.ReadGeneratedFile("exports/tenant_lab_001/2026/05/23/export_stream.ndjson.gz")
	if err != nil {
		t.Fatalf("ReadGeneratedFile returned error: %v", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll returned error: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if !strings.Contains(string(decoded), `"row_001"`) || !strings.Contains(string(decoded), `"row_002"`) {
		t.Fatalf("decoded = %s", decoded)
	}
}

func TestLocalStoreRejectsUnsafePath(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	if _, err := store.WriteGzipJSONL("../outside.ndjson.gz", []map[string]any{{"id": "row_001"}}); err == nil {
		t.Fatalf("WriteGzipJSONL accepted path traversal")
	}
	if _, err := store.ReadGeneratedFile("/tmp/outside.ndjson.gz"); err == nil {
		t.Fatalf("ReadGeneratedFile accepted absolute path")
	}
	if _, err := store.ListGeneratedFiles("../outside", ".gz", 10); err == nil {
		t.Fatalf("ListGeneratedFiles accepted path traversal")
	}
}

func TestLocalStoreListGeneratedFilesFiltersSuffix(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	if _, err := store.WriteGzipJSONL("domain-events/tenant/domain/2026/05/24/event_001.ndjson.gz", []map[string]any{{"id": "event_001"}}); err != nil {
		t.Fatalf("WriteGzipJSONL object returned error: %v", err)
	}
	if _, err := store.WriteGzipJSONL("domain-events/tenant/domain/2026/05/24/event_001.manifest.ndjson.gz", []map[string]any{{"id": "manifest_001"}}); err != nil {
		t.Fatalf("WriteGzipJSONL manifest returned error: %v", err)
	}

	files, err := store.ListGeneratedFiles("domain-events/", ".manifest.ndjson.gz", 10)
	if err != nil {
		t.Fatalf("ListGeneratedFiles returned error: %v", err)
	}
	if len(files) != 1 || files[0] != "domain-events/tenant/domain/2026/05/24/event_001.manifest.ndjson.gz" {
		t.Fatalf("files = %#v", files)
	}
}

func TestLocalStoreRemovesPartialObjectOnStreamError(t *testing.T) {
	dir := t.TempDir()
	store, err := NewLocalStore(dir)
	if err != nil {
		t.Fatalf("NewLocalStore returned error: %v", err)
	}
	filename := "exports/tenant_lab_001/2026/05/23/export_partial.ndjson.gz"

	_, err = store.WriteGzipJSONLStream(filename, func() (map[string]any, bool, error) {
		return nil, false, fmt.Errorf("synthetic stream failure")
	})
	if err == nil {
		t.Fatalf("WriteGzipJSONLStream returned nil error, want failure")
	}
	if _, err := os.Stat(filepath.Join(dir, filename)); !os.IsNotExist(err) {
		t.Fatalf("partial object still exists or stat failed with unexpected error: %v", err)
	}
}
