package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// Use a dedicated database. Each case creates and removes its own schema.
func TestPostgresTenantDeletionFailureAndRetry(t *testing.T) {
	dsn := os.Getenv("DSSE_TENANT_DELETE_TEST_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL fixture not configured")
	}
	for _, stage := range []string{"delete", "tombstone", "commit"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			db, err := sql.Open("postgres", dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			schema := fmt.Sprintf("tenant_delete_%d", time.Now().UnixNano())
			exec := func(stmt string) {
				t.Helper()
				if _, err := db.ExecContext(ctx, stmt); err != nil {
					t.Fatal(err)
				}
			}
			exec("CREATE SCHEMA " + schema)
			defer db.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
			exec("SET search_path TO " + schema)
			store, err := setupPostgresAdminTenantModelStore(ctx, postgresAdminAuthStore{DB: db}, filepath.Join("..", "..", "migrations"), true, model.PolicyBundle{TenantID: "customer"}, "operations", "", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: "operations", Roles: []string{"super_admin", "admin"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: "operator", TenantID: "operations", CreatedByAdminPrincipalID: "operator", Roles: []string{"super_admin", "admin"}, Scopes: []string{"*"}, Status: "active", TokenHash: adminTokenHash("synthetic-pg-delete"), ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
			ledger := enrolledinventory.NewLedger()
			if _, err := ledger.Enroll("device", "customer", "", time.Now().Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
			writer, err := logs.NewWriter(filepath.Join(t.TempDir(), "logs"))
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			outbox := &recordingAdminAuditOutboxDeadReader{}
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), OperatorTenantID: "operations", TenantModelStore: store, AdminAuth: auth, EnrolledLedger: ledger, Writer: writer, AdminAuditOutbox: outbox})
			exec(`CREATE FUNCTION reject_delete_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private database failure'; END $$`)
			table := "admin_tenant_model_deletions"
			switch stage {
			case "delete":
				table = "admin_tenant_models"
				exec("CREATE TRIGGER reject_delete BEFORE DELETE ON " + table + " FOR EACH ROW EXECUTE FUNCTION reject_delete_fixture()")
			case "tombstone":
				exec("CREATE TRIGGER reject_delete BEFORE INSERT ON " + table + " FOR EACH ROW EXECUTE FUNCTION reject_delete_fixture()")
			case "commit":
				exec("CREATE CONSTRAINT TRIGGER reject_delete AFTER INSERT ON " + table + " DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_delete_fixture()")
			}
			generation := store.ConfigGeneration()
			code, raw := operatorEnvelopeCall(t, h, "synthetic-pg-delete", "DELETE", "/admin/tenants/customer", "", nil)
			if code != 503 || strings.Contains(raw, "private database failure") || !strings.Contains(raw, "Reload before retrying") {
				t.Errorf("delete response %d: %s", code, raw)
			}
			var count int
			if err := db.QueryRowContext(ctx, "SELECT count(*) FROM admin_tenant_models WHERE tenant_id='customer'").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 || len(store.DeletedTenants()) != 0 || store.ConfigGeneration() != generation {
				t.Errorf("failed transaction did not preserve registry: rows=%d tombstones=%v generation=%d", count, store.DeletedTenants(), store.ConfigGeneration())
			}
			if row, ok := ledger.EntryFor("device"); !ok || !row.Enabled || row.RemovedAt != "" {
				t.Fatal("failed registry save retired the device")
			}
			exec("DROP TRIGGER reject_delete ON " + table)
			code, raw = operatorEnvelopeCall(t, h, "synthetic-pg-delete", "DELETE", "/admin/tenants/customer", "", nil)
			if code != 200 {
				t.Fatalf("retry %d: %s", code, raw)
			}
			// A new connection reads both committed facts; this does not rely on local state.
			fresh, err := sql.Open("postgres", dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			if err := fresh.QueryRowContext(ctx, "SELECT count(*) FROM "+schema+".admin_tenant_models WHERE tenant_id='customer'").Scan(&count); err != nil || count != 0 {
				t.Fatalf("deleted row count=%d err=%v", count, err)
			}
			if err := fresh.QueryRowContext(ctx, "SELECT count(*) FROM "+schema+".admin_tenant_model_deletions WHERE tenant_id='customer'").Scan(&count); err != nil || count != 1 {
				t.Fatalf("tombstone count=%d err=%v", count, err)
			}
			if store.ConfigGeneration() != generation+1 {
				t.Fatal("successful transaction did not advance generation once")
			}
			if row, ok := ledger.EntryFor("device"); ok && row.Enabled {
				t.Fatal("confirmed deletion left an active device")
			}
			// Repeating deletion still carries the same tenant once, including the ghost case.
			if err := store.Delete(ctx, "customer"); err != nil || len(store.DeletedTenants()) != 1 {
				t.Fatalf("repeat: %v", err)
			}
			outbox.mu.Lock()
			defer outbox.mu.Unlock()
			a := outbox.wrapperAudits
			if len(a) != 2 {
				t.Fatalf("mutation audits=%d", len(a))
			}
			for i, status := range []int{503, 200} {
				result := "error"
				if i == 1 {
					result = "success"
				}
				if a[i].ActorUserID == nil || *a[i].ActorUserID != "operator" || a[i].Result == nil || *a[i].Result != result || a[i].Metadata["status_code"] != status {
					t.Errorf("audit %+v", a[i])
				}
			}
		})
	}
}
