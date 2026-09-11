package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	migrationstore "github.com/lantern-networks/dsse-core/migrations"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestPKIHistoryGuardMigrationIsSelected(t *testing.T) {
	all, err := migrationstore.LoadDir("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := selectPostgresComponentMigrations(all, "cp-state blobs", postgresCPStateBlobsMigrationVersions()...)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range selected {
		if m.Version == "047" {
			found = true
			if len(m.Statements) != 2 {
				t.Fatal("function body was split at internal semicolons")
			}
		}
	}
	if !found {
		t.Fatal("PKI guard omitted from CP migrations")
	}
}

func TestPKIHistoryWriteGuardRejectsLegacyWriterInPostgres(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN not set")
	}
	base, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("pki_guard_%d", time.Now().UnixNano())
	if _, err = base.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer base.Exec("DROP SCHEMA " + schema + " CASCADE")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`CREATE TABLE cp_state_blobs(store_key text PRIMARY KEY,payload bytea NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	if err = requirePKIHistoryWriteGuard(db); err == nil {
		t.Fatal("writer accepted missing guard")
	}
	a := newTenantDeviceAuthority(nil, nil, time.Now)
	for _, tenant := range []string{"tenant_a", "tenant_b"} {
		if _, err = a.EnsureCA(tenant, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err = a.RotateCA(tenant); err != nil {
			t.Fatal(err)
		}
		if _, err = a.RetirePrevious(tenant); err != nil {
			t.Fatal(err)
		}
	}
	store := postgresBlobPersister{db: db, key: "tenant_device_authorities"}
	before := encodeAuthoritySnapshot(a.cas)
	if err = store.Save(before); err != nil {
		t.Fatal(err)
	}
	previousDB := cpStateBlobDB
	cpStateBlobDB = db
	t.Cleanup(func() { cpStateBlobDB = previousDB })
	reg := tenantca.NewTenantCARegistry()
	if _, err = reg.Register("tenant_a", []byte(a.cas["tenant_a"].CACertPEM)); err != nil {
		t.Fatal(err)
	}
	section := deviceCABundleSection(reg, nil)
	if section == nil || !section.ManagedComplete || len(section.ManagedTenants) != 2 {
		t.Fatal("CP without a signer misdeclared the shared managed set as empty")
	}
	all, err := migrationstore.LoadDir("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	selected, err := migrationstore.SelectVersions(all, "047")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = migrationstore.Apply(context.Background(), db, selected); err != nil {
			t.Fatal(err)
		}
	}
	if err = requirePKIHistoryWriteGuard(db); err != nil {
		t.Fatal(err)
	}
	// Simulate an old CP editing B and re-encoding ALL rows through a type which
	// does not carry retirement history. Its unconditional Save must be refused.
	var rows []map[string]any
	if err = json.Unmarshal(before, &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		delete(r, "retired_anchor_sha256")
	}
	oldWriter, _ := json.Marshal(rows)
	for _, write := range []func() error{func() error { return store.Save(oldWriter) }, func() error { return store.CompareAndSwap(before, oldWriter) }} {
		if err = write(); err == nil || !strings.Contains(err.Error(), "pki_history_regression") {
			t.Fatalf("legacy writer not rejected: %v", err)
		}
		held, e := store.Load()
		if e != nil || !bytes.Equal(held, before) {
			t.Fatal("failed write changed persisted authority")
		}
	}
	// The guard itself survives a CP restart: a new persister still cannot forget.
	fresh := postgresBlobPersister{db: db, key: store.key}
	if err = fresh.Save(oldWriter); err == nil {
		t.Fatal("new process bypassed database guard")
	}
	// Normal and abandoned rotations may append history. Tenant erasure may remove
	// its row without changing anybody else's history.
	if _, err = a.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	if _, err = a.AbandonRotation("tenant_a"); err != nil {
		t.Fatal(err)
	}
	if _, err = a.RetirePrevious("tenant_a"); err != nil {
		t.Fatal(err)
	}
	if err = store.Save(encodeAuthoritySnapshot(a.cas)); err != nil {
		t.Fatal(err)
	}
	delete(a.cas, "tenant_a")
	if err = store.Save(encodeAuthoritySnapshot(a.cas)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", store.key); err == nil {
		t.Fatal("whole-store erasure bypassed history")
	}
	if _, err = db.Exec("UPDATE cp_state_blobs SET store_key='moved' WHERE store_key=$1", store.key); err == nil {
		t.Fatal("moving store key bypassed history")
	}
	trust := postgresBlobPersister{db: db, key: "tenant_trust_distributions"}
	baseline := []byte(`{"schema_version":1,"serial_floor":100,"recovery_history_version":1,"tenants":{}}`)
	if err = trust.Save(baseline); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"schema_version":1,"serial_floor":100,"tenants":{}}`,
		`{"schema_version":1,"serial_floor":99,"recovery_history_version":1,"tenants":{}}`,
	} {
		if err = trust.Save([]byte(bad)); err == nil {
			t.Fatal("canonical history regression accepted")
		}
	}
	if err = trust.Save([]byte(`{"schema_version":1,"serial_floor":101,"recovery_history_version":1,"tenants":{}}`)); err != nil {
		t.Fatal(err)
	}
	// Non-PKI state keeps its existing contract.
	ordinary := postgresBlobPersister{db: db, key: "ordinary"}
	if err = ordinary.Save([]byte("not-json")); err != nil {
		t.Fatal(err)
	}
	if err = ordinary.Save([]byte("different")); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DELETE FROM cp_state_blobs WHERE store_key='ordinary'"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("ALTER TABLE cp_state_blobs DISABLE TRIGGER dsse_pki_history_write_guard"); err != nil {
		t.Fatal(err)
	}
	if err = requirePKIHistoryWriteGuard(db); err == nil {
		t.Fatal("disabled guard accepted")
	}
	if _, err = db.Exec("ALTER TABLE cp_state_blobs RENAME TO inaccessible"); err != nil {
		t.Fatal(err)
	}
	section = deviceCABundleSection(reg, nil)
	if section == nil || section.Complete || section.ManagedComplete {
		t.Fatal("failed shared ownership read became an empty complete declaration")
	}
}
