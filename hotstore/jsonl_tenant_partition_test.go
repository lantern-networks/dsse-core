package hotstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestJSONLQueriesDoNotExposeOtherTenantRowCounts(t *testing.T) {
	for _, partitioned := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "partitioned"}[partitioned], func(t *testing.T) {
			w, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if partitioned {
				w.SetTenantPartitionedFiles("events.jsonl")
			}
			for _, tenant := range []string{"tenant-a", "tenant-b", "tenant-b"} {
				if err := w.Append("events.jsonl", map[string]any{"tenant_id": tenant, "id": "event", "access_decision_id": "decision"}); err != nil {
					t.Fatal(err)
				}
			}
			store := NewJSONLStore(w, map[string]string{"events": "events.jsonl"})
			q := SearchQuery{TenantID: "tenant-a", Stream: "events", Limit: 10}
			r, err := store.Search(context.Background(), q)
			if err != nil {
				t.Fatal(err)
			}
			if r.TotalScanned != 1 || len(r.Rows) != 1 {
				t.Errorf("search exposed other tenant rows/count: scanned=%d rows=%d", r.TotalScanned, len(r.Rows))
			}
			e, err := store.ExportRows(context.Background(), q, func(map[string]any) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			if e.TotalScanned != 1 || e.RowsExported != 1 {
				t.Errorf("export exposed other tenant counts: %+v", e)
			}
		})
	}
}

func TestJSONLPartitionQueryDoesNotReadAnotherTenantsBrokenFile(t *testing.T) {
	dir := t.TempDir()
	w, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.SetTenantPartitionedFiles("events.jsonl")
	if err := w.Append("events.jsonl", map[string]any{"tenant_id": "tenant-a", "access_decision_id": "decision"}); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant-b"), "events.jsonl")
	if err := os.MkdirAll(filepath.Dir(foreign), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("broken log\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store := NewJSONLStore(w, map[string]string{"events": "events.jsonl"})
	q := SearchQuery{TenantID: "tenant-a", Stream: "events", Limit: 10}
	if _, err := store.Search(context.Background(), q); err != nil {
		t.Errorf("other tenant blocked search: %v", err)
	}
	if _, err := store.ExportRows(context.Background(), q, func(map[string]any) error { return nil }); err != nil {
		t.Errorf("other tenant blocked export: %v", err)
	}
	if _, err := store.RelatedByAccessDecisionID(context.Background(), RelatedLogQuery{TenantID: "tenant-a", AccessDecisionID: "decision"}); err != nil {
		t.Errorf("other tenant blocked related lookup: %v", err)
	}
}
