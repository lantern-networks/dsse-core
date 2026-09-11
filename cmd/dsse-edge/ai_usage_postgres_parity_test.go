package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	_ "github.com/lib/pq"
)

// The Go-side parity test (ai_usage_grouping_parity_test.go) proves the two paths agree when the grouping is
// correct. This one proves the SQL actually produces that grouping — the part no unit test can assert, because
// the risk lives in the statement: which JSON depth a field is read at, whether a bucket set survives
// string_agg, whether a non-numeric byte count blanks the sum.
//
// Requires a real PostgreSQL. Set DSSE_TEST_POSTGRES_DSN to run it; skipped otherwise so the normal suite does
// not depend on a database. Rows are written under a tenant id nothing else uses and deleted afterwards.
func TestPostgresGroupingMatchesRowLoading(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN to verify the aggregate path against a real PostgreSQL")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}
	for _, statement := range hotstore.PostgresSchemaSQL() {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("apply schema: %v", err)
		}
	}

	const tenant = "tenant_aggregate_parity_test"
	cleanup := func() {
		if _, err := db.ExecContext(context.Background(), `DELETE FROM hot_events WHERE tenant_id = $1`, tenant); err != nil {
			t.Logf("cleanup failed, rows left behind for tenant %s: %v", tenant, err)
		}
	}
	cleanup()
	defer cleanup()

	store := hotstore.NewPostgresStore(db)
	rows := aiParityRows()
	for i, row := range rows {
		row["tenant_id"] = tenant
		row["id"] = "parity-" + time.Now().UTC().Format("150405.000000000") + "-" + string(rune('a'+i))
		occurred, err := time.Parse(time.RFC3339, row["timestamp"].(string))
		if err != nil {
			t.Fatalf("row %d has an unparseable timestamp: %v", i, err)
		}
		if err := store.IngestAt(ctx, "access", row, occurred); err != nil {
			t.Fatalf("ingest row %d: %v", i, err)
		}
	}

	from := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)

	var loaded []map[string]any
	if _, err := store.ExportRows(ctx, hotstore.SearchQuery{
		TenantID: tenant, Stream: "access", From: &from, To: &to, Limit: 1000,
	}, func(row map[string]any) error {
		loaded = append(loaded, row)
		return nil
	}); err != nil {
		t.Fatalf("export rows: %v", err)
	}
	if len(loaded) != len(rows) {
		t.Fatalf("row-loading returned %d rows, want %d — the window or the ingest is wrong before parity is even in question", len(loaded), len(rows))
	}

	grouped, err := store.GroupRowsByFields(ctx, aiUsageGroupQuery(tenant, from, to))
	if err != nil {
		t.Fatalf("group rows: %v", err)
	}
	if len(grouped.Groups) == 0 || len(grouped.Groups) >= len(rows) {
		t.Fatalf("grouping collapsed nothing useful: %d groups for %d rows", len(grouped.Groups), len(rows))
	}
	if grouped.TotalRows != len(rows) {
		t.Fatalf("grouped row total = %d, want %d — a row was dropped or double counted by the GROUP BY", grouped.TotalRows, len(rows))
	}

	const generatedAt = "2026-08-07T12:00:00Z"
	fromRows := buildAIUsageReport(loaded, aiParityCatalog(), generatedAt)
	fromSQL := buildAIUsageReportFromInputs(aiUsageInputsFromGroups(grouped.Groups), aiParityCatalog(), generatedAt)

	a, _ := json.Marshal(fromRows)
	b, _ := json.Marshal(fromSQL)
	if string(a) != string(b) {
		t.Fatalf("the SQL-grouped report differs from the row-loaded one.\n rows: %s\n sql : %s", a, b)
	}
	if fromSQL.TotalAISessions == 0 || fromSQL.TotalAIAccesses == 0 {
		t.Fatalf("both paths agree on an empty report, which proves nothing: %s", b)
	}
}
