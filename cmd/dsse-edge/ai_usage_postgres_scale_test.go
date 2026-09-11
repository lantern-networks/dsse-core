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

// The whole premise of the aggregate path is a measurement from the past: row-loading 100k rows out of the
// control plane's Postgres and aggregating them in Go took long enough that the Console timed out, which is why
// the report is served from the edge's local file to this day. This test re-measures BOTH paths at that scale
// against a real database, so the premise is a number rather than a memory — and it compares the two reports at
// 100k rows, which is a far harsher parity check than the five-row one.
//
// Opt-in twice over: it needs DSSE_TEST_POSTGRES_DSN and it writes ~100k rows, so it also needs
// DSSE_TEST_POSTGRES_SCALE=1. Rows go under a tenant nothing else uses and are deleted afterwards.
func TestPostgresAggregateVersusRowLoadingAtScale(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" || os.Getenv("DSSE_TEST_POSTGRES_SCALE") == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN and DSSE_TEST_POSTGRES_SCALE=1 to measure both paths at 100k rows")
	}
	rowCount := 100000
	if raw := os.Getenv("DSSE_TEST_POSTGRES_SCALE_ROWS"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			rowCount = n
		}
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}
	for _, statement := range hotstore.PostgresSchemaSQL() {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("apply schema: %v", err)
		}
	}

	const tenant = "tenant_aggregate_scale_test"
	cleanup := func() {
		if _, err := db.ExecContext(context.Background(), `DELETE FROM hot_events WHERE tenant_id = $1`, tenant); err != nil {
			t.Logf("cleanup failed, rows left behind for tenant %s: %v", tenant, err)
		}
	}
	cleanup()
	defer cleanup()

	// A shape a real tenant would produce: a modest number of people and devices generating a large number of
	// rows. That ratio is the entire argument for grouping in the database, so the test has to have it.
	users := 20
	devices := 2
	apps := 3
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	window := 7 * 24 * time.Hour

	// Seeded by the server with generate_series rather than by shipping 100k INSERTs from here: building the
	// rows client-side took nearly three minutes, which made the measurement tedious enough to skip.
	t.Logf("seeding %d rows...", rowCount)
	seedStart := time.Now()
	seed := `
INSERT INTO hot_events (tenant_id, stream, event_id, occurred_at, received_at, payload)
SELECT $1::text, 'access', 'scale-' || i,
       $2::timestamptz + ($3::interval * i / $4::int),
       $2::timestamptz + ($3::interval * i / $4::int),
       jsonb_build_object(
         'tenant_id', $1::text,
         'id', 'scale-' || i,
         'saas_application_id', (ARRAY['saas_anthropic_claude','saas_openai_chatgpt','saas_google_gemini'])[1 + (i % 3)],
         'saas_name',           (ARRAY['saas_anthropic_claude','saas_openai_chatgpt','saas_google_gemini'])[1 + (i % 3)],
         'user_id', 'user' || lpad((i % $5::int)::text, 2, '0') || '@example.com',
         'device_id', 'device-' || (i % $6::int),
         'timestamp', to_char($2::timestamptz + ($3::interval * i / $4::int), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
         'metadata', jsonb_build_object(
            'ai_app', 'app-' || (i % $7::int),
            'ai_account', 'user' || lpad((i % $5::int)::text, 2, '0') || '@example.com',
            'ai_email',   'user' || lpad((i % $5::int)::text, 2, '0') || '@example.com',
            'http_method', (ARRAY['GET','POST'])[1 + (i % 2)],
            'bytes_sent', 100,
            'bytes_received', 900))
FROM generate_series($8::int, $8::int + $9::int - 1) AS i
ON CONFLICT DO NOTHING`
	// In chunks. One statement for the whole set is a single transaction that extends the table file in one
	// burst, and on the lab's containerised disk that was slower than shipping the rows from here — the opposite
	// of the intended saving. Chunking keeps the server-side generation and spreads the writes.
	const seedChunk = 10000
	for start := 0; start < rowCount; start += seedChunk {
		size := seedChunk
		if start+size > rowCount {
			size = rowCount - start
		}
		if _, err := db.ExecContext(ctx, seed, tenant, base, window.String(), rowCount, users, devices, apps, start, size); err != nil {
			t.Fatalf("seed chunk at %d: %v", start, err)
		}
	}
	t.Logf("seeded in %s", time.Since(seedStart).Round(time.Millisecond))

	store := hotstore.NewPostgresStore(db)
	from := base.Add(-time.Hour)
	to := base.Add(window + time.Hour)
	catalog := aiParityCatalog()
	const generatedAt = "2026-08-08T00:00:00Z"

	rowStart := time.Now()
	var loaded []map[string]any
	if _, err := store.ExportRows(ctx, hotstore.SearchQuery{
		TenantID: tenant, Stream: "access", From: &from, To: &to, Limit: rowCount,
	}, func(row map[string]any) error {
		loaded = append(loaded, row)
		return nil
	}); err != nil {
		t.Fatalf("export rows: %v", err)
	}
	fromRows := buildAIUsageReport(loaded, catalog, generatedAt)
	rowElapsed := time.Since(rowStart)

	aggStart := time.Now()
	grouped, err := store.GroupRowsByFields(ctx, aiUsageGroupQuery(tenant, from, to))
	if err != nil {
		t.Fatalf("group rows: %v", err)
	}
	fromSQL := buildAIUsageReportFromInputs(aiUsageInputsFromGroups(grouped.Groups), catalog, generatedAt)
	aggElapsed := time.Since(aggStart)

	// Same grouping without the session-bucket set, to say WHICH part of the aggregate costs what. string_agg
	// over DISTINCT computed buckets is the one operation here that cannot be answered from a running total.
	noBucketStart := time.Now()
	if _, err := store.GroupRowsByFields(ctx, aiUsageGroupQuery(tenant, from, to)); err != nil {
		t.Fatalf("group rows without buckets: %v", err)
	}
	noBucketElapsed := time.Since(noBucketStart)

	t.Logf("row-loading: %d rows -> %s", len(loaded), rowElapsed.Round(time.Millisecond))
	t.Logf("aggregate  : %d groups -> %s", len(grouped.Groups), aggElapsed.Round(time.Millisecond))
	t.Logf("aggregate without the session-bucket set -> %s", noBucketElapsed.Round(time.Millisecond))
	if aggElapsed > 0 {
		t.Logf("speedup    : %.1fx", float64(rowElapsed)/float64(aggElapsed))
	}

	if len(loaded) != rowCount {
		t.Fatalf("row-loading returned %d rows, want %d", len(loaded), rowCount)
	}
	if grouped.TotalRows != rowCount {
		t.Fatalf("grouped row total = %d, want %d — the GROUP BY dropped or duplicated rows", grouped.TotalRows, rowCount)
	}
	a, _ := json.Marshal(fromRows)
	b, _ := json.Marshal(fromSQL)
	if string(a) != string(b) {
		t.Fatalf("at %d rows the two paths disagree.\n rows: %.4000s\n sql : %.4000s", rowCount, a, b)
	}
	// The claim being tested is not "the aggregate is faster in principle" but "it is the path that can serve
	// this from the control plane". Fail if it is not decisively better, so the claim cannot rot silently.
	if aggElapsed >= rowElapsed {
		t.Fatalf("the aggregate (%s) was not faster than row-loading (%s) at %d rows — the premise of the whole path", aggElapsed, rowElapsed, rowCount)
	}
}
