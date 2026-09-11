package hotstore

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
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
	migrations, err := migrationstore.LoadDir(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatalf("load postgres hot store migrations: %v", err)
	}
	if err := migrationstore.Apply(ctx, db, migrations); err != nil {
		t.Fatalf("apply postgres hot store migrations: %v", err)
	}
}
