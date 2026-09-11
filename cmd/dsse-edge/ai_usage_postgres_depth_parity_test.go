package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	_ "github.com/lib/pq"
)

// The row-loading path reads each field at ONE specific depth, and they are not the same depth for every field:
// user_id and device_id are top-level only, ai_account and ai_app are under metadata only, saas_application_id
// is top-level with a metadata fallback, and bytes_sent is a metadata JSON *number* (a string "100" reads as
// zero). If the SQL looks anywhere else, the two paths disagree about a row — quietly, and only for rows shaped
// unusually enough that no ordinary test contains one.
//
// So this test contains one. Every field here sits at the depth the Go reader does NOT look at, plus byte counts
// in the two shapes Go rejects or truncates. The correct outcome is that both paths reach the same report by
// ignoring the same things.
func TestPostgresGroupingMatchesRowLoadingForOddlyShapedRows(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN to verify depth handling against a real PostgreSQL")
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

	const tenant = "tenant_depth_parity_test"
	cleanup := func() {
		if _, err := db.ExecContext(context.Background(), `DELETE FROM hot_events WHERE tenant_id = $1`, tenant); err != nil {
			t.Logf("cleanup failed, rows left behind for tenant %s: %v", tenant, err)
		}
	}
	cleanup()
	defer cleanup()

	at := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	rows := []map[string]any{
		// user_id ONLY under metadata: the Go reader never sees it, so this row is unattributed to a corporate
		// user. A COALESCE that falls through to metadata would attribute it, and invent a person.
		{
			"tenant_id": tenant, "id": "odd-1", "timestamp": at.Format(time.RFC3339),
			"saas_application_id": "saas_anthropic_claude", "saas_name": "saas_anthropic_claude",
			"device_id": "mac-1",
			"metadata":  map[string]any{"user_id": "ghost@example.com", "bytes_sent": 10, "bytes_received": 20},
		},
		// ai_account at TOP level: the Go reader only looks under metadata, so this is not an AI account.
		{
			"tenant_id": tenant, "id": "odd-2", "timestamp": at.Add(time.Minute).Format(time.RFC3339),
			"saas_application_id": "saas_anthropic_claude", "saas_name": "saas_anthropic_claude",
			"device_id": "mac-1", "ai_account": "top-level@example.com",
			"metadata": map[string]any{"bytes_sent": 10, "bytes_received": 20},
		},
		// saas_application_id ONLY under metadata: here the Go reader DOES fall back, so this row must count.
		{
			"tenant_id": tenant, "id": "odd-3", "timestamp": at.Add(2 * time.Minute).Format(time.RFC3339),
			"device_id": "mac-1",
			"metadata": map[string]any{
				"saas_application_id": "saas_openai_chatgpt", "saas_name": "saas_openai_chatgpt",
				"bytes_sent": 10, "bytes_received": 20,
			},
		},
		// bytes as a STRING and as a FLOAT: Go reads a JSON number, so "100" counts as zero and 10.9 truncates.
		{
			"tenant_id": tenant, "id": "odd-4", "timestamp": at.Add(3 * time.Minute).Format(time.RFC3339),
			"saas_application_id": "saas_anthropic_claude", "saas_name": "saas_anthropic_claude",
			"device_id": "mac-2",
			"metadata":  map[string]any{"bytes_sent": "100", "bytes_received": 10.9},
		},
		// http_method at TOP level: isAIMessage only looks under metadata, so this is not a message.
		{
			"tenant_id": tenant, "id": "odd-5", "timestamp": at.Add(4 * time.Minute).Format(time.RFC3339),
			"saas_application_id": "saas_anthropic_claude", "saas_name": "saas_anthropic_claude",
			"device_id": "mac-2", "http_method": "POST",
			"metadata": map[string]any{"bytes_sent": 1, "bytes_received": 1},
		},
	}

	store := hotstore.NewPostgresStore(db)
	for i, row := range rows {
		occurred, err := time.Parse(time.RFC3339, row["timestamp"].(string))
		if err != nil {
			t.Fatalf("row %d timestamp: %v", i, err)
		}
		if err := store.IngestAt(ctx, "access", row, occurred); err != nil {
			t.Fatalf("ingest row %d: %v", i, err)
		}
	}

	from := at.Add(-time.Hour)
	to := at.Add(time.Hour)
	var loaded []map[string]any
	if _, err := store.ExportRows(ctx, hotstore.SearchQuery{
		TenantID: tenant, Stream: "access", From: &from, To: &to, Limit: 100,
	}, func(row map[string]any) error {
		loaded = append(loaded, row)
		return nil
	}); err != nil {
		t.Fatalf("export rows: %v", err)
	}
	if len(loaded) != len(rows) {
		t.Fatalf("row-loading returned %d rows, want %d", len(loaded), len(rows))
	}

	grouped, err := store.GroupRowsByFields(ctx, aiUsageGroupQuery(tenant, from, to))
	if err != nil {
		t.Fatalf("group rows: %v", err)
	}

	const generatedAt = "2026-08-08T00:00:00Z"
	fromRows := buildAIUsageReport(loaded, aiParityCatalog(), generatedAt)
	fromSQL := buildAIUsageReportFromInputs(aiUsageInputsFromGroups(grouped.Groups), aiParityCatalog(), generatedAt)

	a, _ := json.Marshal(fromRows)
	b, _ := json.Marshal(fromSQL)
	if string(a) != string(b) {
		t.Fatalf("the two paths read these rows differently.\n rows: %s\n sql : %s", a, b)
	}
	// Guard against both paths agreeing on nothing: odd-3 must have been counted via the metadata fallback.
	if fromSQL.TotalAIAccesses != len(rows) {
		t.Fatalf("expected all %d rows to count as AI accesses, got %d: %s", len(rows), fromSQL.TotalAIAccesses, b)
	}
}

// The report states how far its records actually reach (coverage.retained_from). That fact was only computed on
// the row-loading path at first, so switching a deployment to the aggregate would have made it silently vanish —
// the screen would go back to implying full coverage of whatever period was selected. Both paths must answer.
func TestBothPathsReportTheSameRetentionHorizon(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN to compare the retention horizon across both paths")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, statement := range hotstore.PostgresSchemaSQL() {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("apply schema: %v", err)
		}
	}
	const tenant = "tenant_horizon_parity_test"
	cleanup := func() { db.ExecContext(context.Background(), `DELETE FROM hot_events WHERE tenant_id = $1`, tenant) }
	cleanup()
	defer cleanup()

	store := hotstore.NewPostgresStore(db)
	oldest := time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC)
	for i, at := range []time.Time{oldest, oldest.Add(48 * time.Hour)} {
		row := map[string]any{
			"tenant_id": tenant, "id": "horizon-" + strconv.Itoa(i), "timestamp": at.Format(time.RFC3339),
			"saas_application_id": "saas_anthropic_claude", "saas_name": "saas_anthropic_claude",
			"user_id": "a@example.com", "device_id": "mac-1",
			"metadata": map[string]any{"bytes_sent": 1, "bytes_received": 1},
		}
		if err := store.IngestAt(ctx, "access", row, at); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}

	// A window that starts BEFORE the oldest record: both paths must report the horizon, not silence.
	from := oldest.Add(-72 * time.Hour)
	to := oldest.Add(96 * time.Hour)

	export, err := store.ExportRows(ctx, hotstore.SearchQuery{
		TenantID: tenant, Stream: "access", From: &from, To: &to, Limit: 100, IncludeOldestMatched: true,
	}, func(map[string]any) error { return nil })
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	grouped, err := store.GroupRowsByFields(ctx, aiUsageGroupQuery(tenant, from, to))
	if err != nil {
		t.Fatalf("group: %v", err)
	}
	if export.OldestMatchedAt.IsZero() || grouped.OldestMatchedAt.IsZero() {
		t.Fatalf("a path reported no horizon: rows=%s aggregate=%s", export.OldestMatchedAt, grouped.OldestMatchedAt)
	}
	if !export.OldestMatchedAt.Equal(grouped.OldestMatchedAt) {
		t.Fatalf("the two paths disagree on the horizon: rows=%s aggregate=%s", export.OldestMatchedAt, grouped.OldestMatchedAt)
	}
	if !grouped.OldestMatchedAt.Equal(oldest) {
		t.Fatalf("horizon = %s, want the oldest ingested record %s", grouped.OldestMatchedAt, oldest)
	}
}
