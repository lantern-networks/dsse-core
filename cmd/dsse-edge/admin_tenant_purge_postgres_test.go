package main

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/policyrule"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
)

func TestPostgresTenantPurgeWithCredentialWriterProtocol(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("purge_protocol_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	scoped := dsn + " search_path=" + schema
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		scoped = u.String()
	}
	db, err := sql.Open("postgres", scoped)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	all, err := migrationstore.LoadDir("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := selectPostgresComponentMigrations(all, "purge fixture", "020", "038", "041", "048", "049", "051")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrationstore.Apply(ctx, db, selected); err != nil {
		t.Fatal(err)
	}
	p := postgresCredentialPersistence{db: db}
	now := time.Now().UTC()
	load := func() *localAdminCredentialStore {
		s, e := newLocalAdminCredentialStoreWithPersistence("DSSE", p)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	mark := func(tenant string) {
		for _, table := range []string{"admin_tenant_model_deletions", "admin_tenant_model_purge_orders"} {
			if _, err := db.ExecContext(ctx, "INSERT INTO "+table+" VALUES ($1,$2)", tenant, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	count := func(table, tenant string) int {
		var n int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	purge := func(tenant string, store *localAdminCredentialStore) adminTenantPurgeResult {
		return purgeAdminTenantData(ctx, "node", tenant, db, nil, store, nil, nil, nil, "", nil, nil, adminTenantExtraStores{}, nil, now)
	}
	assertMarks := func(tenant string, n int) {
		for _, table := range []string{"admin_tenant_model_deletions", "admin_tenant_model_purge_orders"} {
			if got := count(table, tenant); got != n {
				t.Fatalf("%s: got %d want %d", table, got, n)
			}
		}
	}
	t.Run("rule_save_failure_keeps_retired_inventory_and_fleet_marks", func(t *testing.T) {
		tenant := "tenant_rules_failed"
		dir := t.TempDir()
		path := filepath.Join(dir, "rules.json")
		inventory := blobstore.FilePersister{Path: filepath.Join(dir, "inventory.json")}
		rules := policyrule.NewStore()
		if err := rules.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
			t.Fatal(err)
		}
		ledger := enrolledinventory.NewLedger()
		if err := ledger.SetPersisterChecked(inventory); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{tenant, "tenant_rules_other"} {
			if _, err := rules.Upsert(policyrule.Rule{ID: "rule-" + id, TenantID: id, Plane: policyrule.PlaneEgress, Priority: 100, Source: []string{"*"}, Destination: []string{"*"}, ServiceID: "builtin-svc-https", Action: policyrule.Action{Access: "deny", Inspection: "inspect"}, Status: "active"}); err != nil {
				t.Fatal(err)
			}
			if _, err := ledger.Enroll("device-"+id, id, "", now.Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
		}
		mark(tenant)
		// A real filesystem refusal: replacement cannot rename over a directory.
		if err := os.Rename(path, path+".saved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		result := purgeAdminTenantData(ctx, "node", tenant, db, nil, nil, ledger, rules, nil, "", nil, nil, adminTenantExtraStores{}, nil, now)
		if result.Complete || len(result.Failures) == 0 {
			t.Errorf("rule persistence failure must be explicit: %+v", result)
		}
		if len(rules.List(tenant, "")) != 1 {
			t.Error("failed erasure changed rules")
		}
		for _, table := range []string{"admin_tenant_model_deletions", "admin_tenant_model_purge_orders"} {
			if count(table, tenant) != 1 {
				t.Errorf("lost durable retry mark %s", table)
			}
		}
		retired := false
		for _, e := range ledger.Authoritative() {
			if e.TenantID == tenant {
				retired = !e.Enabled && e.RemovedAt != ""
			}
		}
		if !retired {
			t.Error("failed erasure lost retired inventory identity")
		}
		for _, row := range result.Erased {
			if row.Store == "authored_rules" {
				t.Error("unconfirmed rule erasure counted")
			}
		}
		if strings.Contains(strings.Join(result.Failures, " "), dir) {
			t.Error("filesystem path leaked")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".saved", path); err != nil {
			t.Fatal(err)
		}
		rules = policyrule.NewStore()
		if err := rules.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
			t.Fatal(err)
		}
		ledger = enrolledinventory.NewLedger()
		if err := ledger.SetPersisterChecked(inventory); err != nil {
			t.Fatal(err)
		}
		result = purgeAdminTenantData(ctx, "node", tenant, db, nil, nil, ledger, rules, nil, "", nil, nil, adminTenantExtraStores{}, nil, now)
		if !result.Complete {
			t.Fatalf("restart retry failed: %+v", result)
		}
		assertMarks(tenant, 0)
		if len(rules.List(tenant, "")) != 0 || len(rules.List("tenant_rules_other", "")) != 1 {
			t.Fatal("retry rule scope")
		}
		entries := ledger.Authoritative()
		if len(entries) != 1 || entries[0].TenantID != "tenant_rules_other" || !entries[0].Enabled {
			t.Fatal("retry inventory scope")
		}
	})
	t.Run("residual_batches_and_empty", func(t *testing.T) {
		// More than one batch, with no in-memory credential store on this node.
		if _, err := credentialFixtureExec(ctx, p, `INSERT INTO admin_local_credentials(email,principal_id,tenant_id,status) SELECT 'batch-'||n||'@example.invalid','batch-'||n,'tenant_batch','pending_activation' FROM generate_series(1,5001) n`); err != nil {
			t.Fatal(err)
		}
		if _, err := load().Invite("other@example.invalid", "tenant_other", "other", []string{"admin"}, now); err != nil {
			t.Fatal(err)
		}
		mark("tenant_batch")
		result := purge("tenant_batch", nil)
		if !result.Complete || len(result.Failures) != 0 {
			t.Fatalf("purge failed: %+v", result)
		}
		var deleted int64
		for _, row := range result.Erased {
			if row.Store == "postgres.admin_local_credentials" {
				deleted = row.Count
			}
		}
		if deleted != 5001 || count("admin_local_credentials", "tenant_other") != 1 {
			t.Fatalf("batch count/scope: %d", deleted)
		}
		assertMarks("tenant_batch", 0)
		if result := purge("tenant_batch", nil); !result.Complete {
			t.Fatalf("zero-row cleanup failed: %+v", result)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM admin_local_credentials WHERE tenant_id='absent'`); err == nil {
			t.Fatal("protocol leaked into pooled connection")
		}
	})
	t.Run("normal_account_delete_then_zero_row_sweep", func(t *testing.T) {
		store := load()
		if _, err := store.Invite("normal@example.invalid", "tenant_normal", "normal", []string{"admin"}, now); err != nil {
			t.Fatal(err)
		}
		mark("tenant_normal")
		result := purge("tenant_normal", store)
		if !result.Complete {
			t.Fatalf("normal purge failed: %+v", result)
		}
		assertMarks("tenant_normal", 0)
	})
	t.Run("commit_failure_keeps_orders_and_rows", func(t *testing.T) {
		if _, err := load().Invite("failed@example.invalid", "tenant_failed", "failed", []string{"admin"}, now); err != nil {
			t.Fatal(err)
		}
		mark("tenant_failed")
		if _, err := db.ExecContext(ctx, `CREATE FUNCTION reject_purge_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'purge commit rejected'; END $$;
CREATE CONSTRAINT TRIGGER reject_purge_commit AFTER DELETE ON admin_local_credentials DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_purge_commit()`); err != nil {
			t.Fatal(err)
		}
		result := purge("tenant_failed", nil)
		if result.Complete || len(result.Failures) == 0 || count("admin_local_credentials", "tenant_failed") != 1 {
			t.Fatalf("failure hidden: %+v", result)
		}
		for _, row := range result.Erased {
			if row.Store == "postgres.admin_local_credentials" && row.Count != 0 {
				t.Fatal("uncommitted deletion counted")
			}
		}
		assertMarks("tenant_failed", 1)
		if _, err := db.ExecContext(ctx, `DROP TRIGGER reject_purge_commit ON admin_local_credentials`); err != nil {
			t.Fatal(err)
		}
		if result := purge("tenant_failed", nil); !result.Complete {
			t.Fatalf("retry failed: %+v", result)
		}
	})
	t.Run("stale_account_failure_not_bypassed_by_sweep", func(t *testing.T) {
		current := load()
		if _, err := current.Invite("replace@example.invalid", "tenant_replace", "old", []string{"admin"}, now); err != nil {
			t.Fatal(err)
		}
		stale := load()
		if _, err := current.Delete("tenant_replace", "old", now); err != nil {
			t.Fatal(err)
		}
		if _, err := current.Invite("replace@example.invalid", "tenant_replace", "new", []string{"admin"}, now); err != nil {
			t.Fatal(err)
		}
		mark("tenant_replace")
		result := purge("tenant_replace", stale)
		if result.Complete || count("admin_local_credentials", "tenant_replace") != 1 {
			t.Fatalf("stale refusal bypassed: %+v", result)
		}
		assertMarks("tenant_replace", 1)
		if result := purge("tenant_replace", load()); !result.Complete {
			t.Fatalf("fresh retry failed: %+v", result)
		}
	})
}
