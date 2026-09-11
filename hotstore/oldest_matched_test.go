package hotstore

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

// newTestStore writes the rows through a real logs.Writer, the way the edge does, so the test exercises the
// same read path rather than a shape invented for the test.
func newTestStore(t *testing.T, rows []map[string]any) *JSONLStore {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for _, row := range rows {
		if err := writer.Append("access.log.jsonl", row); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	return NewJSONLStore(writer, map[string]string{"access": "access.log.jsonl"})
}

// A window can be wider than the answer for two different reasons — the read was capped, or nothing that old is
// held any more — and a report that cannot tell them apart implies coverage it does not have. OldestMatchedAt is
// the second fact. It must see rows the window EXCLUDES, must respect the tenant filter, and must stay zero when
// nobody asked for it (it is free on this backend but not on every one).
func TestExportRowsReportsOldestMatchedOutsideTheWindow(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	store := newTestStore(t, []map[string]any{
		{"tenant_id": "acme", "timestamp": at(-40 * 24 * time.Hour), "id": "ancient"},
		{"tenant_id": "acme", "timestamp": at(-2 * time.Hour), "id": "recent"},
		{"tenant_id": "other", "timestamp": at(-90 * 24 * time.Hour), "id": "other-tenant-older-still"},
	})

	from := now.Add(-24 * time.Hour)
	var got []string
	res, err := store.ExportRows(context.Background(), SearchQuery{
		TenantID: "acme", Stream: "access", From: &from, Limit: 100, IncludeOldestMatched: true,
	}, func(row map[string]any) error {
		got = append(got, row["id"].(string))
		return nil
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 1 || got[0] != "recent" {
		t.Fatalf("window should have yielded only the recent row, got %v", got)
	}
	if want := now.Add(-40 * 24 * time.Hour); !res.OldestMatchedAt.Equal(want) {
		t.Fatalf("OldestMatchedAt = %s, want %s (the row OUTSIDE the window is the whole point)", res.OldestMatchedAt, want)
	}
}

// The horizon is per tenant. Reporting another tenant's older record would leak that they were active.
func TestOldestMatchedIsTenantScoped(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	store := newTestStore(t, []map[string]any{
		{"tenant_id": "acme", "timestamp": at(-3 * time.Hour), "id": "a"},
		{"tenant_id": "other", "timestamp": at(-365 * 24 * time.Hour), "id": "b"},
	})
	from := now.Add(-24 * time.Hour)
	res, err := store.ExportRows(context.Background(), SearchQuery{
		TenantID: "acme", Stream: "access", From: &from, Limit: 100, IncludeOldestMatched: true,
	}, func(map[string]any) error { return nil })
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if want := now.Add(-3 * time.Hour); !res.OldestMatchedAt.Equal(want) {
		t.Fatalf("OldestMatchedAt = %s, want %s — another tenant's row must not set this tenant's horizon", res.OldestMatchedAt, want)
	}
}

func TestOldestMatchedStaysZeroWhenNotRequested(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	store := newTestStore(t, []map[string]any{
		{"tenant_id": "acme", "timestamp": now.Add(-time.Hour).Format(time.RFC3339), "id": "a"},
	})
	res, err := store.ExportRows(context.Background(), SearchQuery{TenantID: "acme", Stream: "access", Limit: 10},
		func(map[string]any) error { return nil })
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !res.OldestMatchedAt.IsZero() {
		t.Fatalf("OldestMatchedAt = %s, want zero when the caller did not opt in", res.OldestMatchedAt)
	}
}
