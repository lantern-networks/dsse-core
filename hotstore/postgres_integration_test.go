package hotstore

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

func TestPostgresHotStoreE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open returned error: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PingContext returned error: %v", err)
	}
	resetPostgresHotStoreTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresHotStoreTables(t, cleanupCtx, db)
		_ = db.Close()
	})
	applyPostgresHotStoreMigrations(t, ctx, db)
	store := NewPostgresStore(db)
	insertHotEventForTest(t, ctx, store, "access", map[string]any{
		"tenant_id":          "tenant_lab_001",
		"stream":             "access",
		"event_id":           "evt_pg_001",
		"access_decision_id": "dec_pg_001",
		"timestamp":          "2026-05-23T03:00:00Z",
		"decision":           "allow",
		"application_id":     "app_dummy_https",
	})
	insertHotEventForTest(t, ctx, store, "access", map[string]any{
		"tenant_id":          "tenant_other_001",
		"stream":             "access",
		"event_id":           "evt_pg_002",
		"access_decision_id": "dec_pg_002",
		"timestamp":          "2026-05-23T03:00:00Z",
		"decision":           "deny",
		"application_id":     "app_other_https",
	})

	result, err := store.Search(ctx, SearchQuery{
		TenantID: "tenant_lab_001",
		Stream:   "access",
		Filters:  map[string]string{"decision": "allow"},
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("Search returned error: %v", err)
	}
	if result.TotalMatches != 1 || len(result.Rows) != 1 || result.Rows[0]["event_id"] != "evt_pg_001" {
		t.Fatalf("search result = %#v", result)
	}
	exported := 0
	exportResult, err := store.ExportRows(ctx, SearchQuery{TenantID: "tenant_lab_001", Stream: "access", Limit: 10}, func(row map[string]any) error {
		exported++
		return nil
	})
	if err != nil {
		t.Fatalf("ExportRows returned error: %v", err)
	}
	if exported != 1 || exportResult.RowsExported != 1 || exportResult.TotalMatches != 1 {
		t.Fatalf("exported=%d exportResult=%#v", exported, exportResult)
	}
	related, err := store.RelatedByAccessDecisionID(ctx, RelatedLogQuery{TenantID: "tenant_lab_001", AccessDecisionID: "dec_pg_001"})
	if err != nil {
		t.Fatalf("RelatedByAccessDecisionID returned error: %v", err)
	}
	if related.TotalRows != 1 || len(related.RowsByStream["access"]) != 1 {
		t.Fatalf("related = %#v", related)
	}
}

func insertHotEventForTest(t *testing.T, ctx context.Context, store *PostgresStore, stream string, payload map[string]any) {
	t.Helper()
	if err := store.Ingest(ctx, stream, payload); err != nil {
		t.Fatalf("insert hot event: %v", err)
	}
}

func resetPostgresHotStoreTables(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for _, statement := range []string{
		"DROP TABLE IF EXISTS admin_audit_outbox",
		"DROP TABLE IF EXISTS hot_events",
		"DROP TABLE IF EXISTS export_worker_task_dead_letters",
		"DROP TABLE IF EXISTS export_worker_tasks",
		"DROP TABLE IF EXISTS admin_export_jobs",
		"DROP TABLE IF EXISTS schema_migrations",
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("reset postgres hot store table with %q: %v", statement, err)
		}
	}
}

func applyPostgresHotStoreMigrations(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	migrations, err := migrationstore.LoadDir(filepath.Join("..", "migrations"))
	if err != nil {
		t.Fatalf("load postgres hot store migrations: %v", err)
	}
	selected, err := migrationstore.SelectVersions(migrations, "003", "010", "050", "052")
	if err != nil {
		t.Fatalf("select postgres hot store migrations: %v", err)
	}
	if err := migrationstore.Apply(ctx, db, selected); err != nil {
		t.Fatalf("apply postgres hot store migrations: %v", err)
	}
}

func TestPostgresLiteralSearchAndMatchingHorizonE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	resetPostgresHotStoreTables(t, ctx, db)
	for _, statement := range PostgresSchemaSQL() {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresHotStoreTables(t, cleanupCtx, db)
	})
	store := NewPostgresStore(db)
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	rows := []struct {
		id, tenant, decision, region, text string
		age                                time.Duration
	}{
		{"old-allow", "own", "allow", "region-a", "needle", 72 * time.Hour},
		{"old-deny", "own", "deny", "region-a", "needle", 48 * time.Hour},
		{"new-deny", "own", "deny", "region-a", "needle", time.Hour},
		{"other-region", "own", "deny", "region-b", "needle", 120 * time.Hour},
		{"other-tenant", "foreign", "deny", "region-a", "needle", 168 * time.Hour},
		{"literal", "own", "allow", "region-a", "100%_done", time.Hour},
		{"wildcard", "own", "allow", "region-a", "100abcXdone", time.Hour},
	}
	for _, row := range rows {
		insertHotEventForTest(t, ctx, store, "access", map[string]any{"event_id": row.id, "tenant_id": row.tenant, "decision": row.decision, "edge_region_id": row.region, "message": row.text, "timestamp": now.Add(-row.age).Format(time.RFC3339)})
	}
	result, err := store.Search(ctx, SearchQuery{TenantID: "own", Stream: "access", Text: "100%_done", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 1 || result.Rows[0]["event_id"] != "literal" {
		t.Fatalf("literal query broadened results: %+v", result)
	}
	from := now.Add(-6 * time.Hour)
	var exported []string
	report, err := store.ExportRows(ctx, SearchQuery{TenantID: "own", Stream: "access", Filters: map[string]string{"decision": "deny", "edge_region_id": "region-a"}, Text: "needle", From: &from, To: &now, Limit: 100, IncludeOldestMatched: true}, func(row map[string]any) error { exported = append(exported, row["event_id"].(string)); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(exported) != 1 || exported[0] != "new-deny" {
		t.Fatalf("unexpected export rows %v", exported)
	}
	if want := now.Add(-48 * time.Hour); !report.OldestMatchedAt.Equal(want) {
		t.Fatalf("horizon=%s, want matching event %s", report.OldestMatchedAt, want)
	}
}

// Compare the resulting database structure, not SQL spelling: migrations add
// columns after CREATE TABLE while the helper can include them from the start.
func TestPostgresHotEventsMigrationMatchesSchemaSQL(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresHotStoreTables(t, cleanupCtx, db)
	})
	resetPostgresHotStoreTables(t, ctx, db)
	applyPostgresHotStoreMigrations(t, ctx, db)
	migrated := hotEventsSchemaForTest(t, ctx, db)
	if _, err := db.ExecContext(ctx, "DROP TABLE hot_events"); err != nil {
		t.Fatal(err)
	}
	for _, statement := range PostgresSchemaSQL() {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	helper := hotEventsSchemaForTest(t, ctx, db)
	if !reflect.DeepEqual(migrated, helper) {
		t.Fatalf("migration/helper schema mismatch: migrated=%v helper=%v", migrated, helper)
	}
}

func hotEventsSchemaForTest(t *testing.T, ctx context.Context, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
 SELECT definition FROM (
  SELECT 'column:' || a.attname || ':' || pg_catalog.format_type(a.atttypid, a.atttypmod) || ':' || a.attnotnull::text || ':' || COALESCE(pg_get_expr(d.adbin, d.adrelid), '') AS definition
   FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE a.attrelid='hot_events'::regclass AND a.attnum > 0 AND NOT a.attisdropped
  UNION ALL SELECT 'index:' || pg_get_indexdef(indexrelid) FROM pg_index WHERE indrelid='hot_events'::regclass
  UNION ALL SELECT 'constraint:' || pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='hot_events'::regclass
 ) s ORDER BY definition`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		out = append(out, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
