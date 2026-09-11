package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ THE TENANT CATALOG HAD TO BE CARRIED, NOT RE-SEEDED (2026-08-18).
//
// Moving -tenant-model-store from a file to postgres seeded two rows — the bundle tenant and the operator
// tenant — and carried nothing else. Measured on the reference deployment: the file held 4 organizations, 26
// deletion tombstones and 28 erasure orders, while Postgres held one row, and two of the missing organizations
// had administrators sitting in admin_principals in the same database.
//
// The tombstones are the sharp half. The bundle's tenant section UPSERTs, so a deletion only travels if it is
// NAMED, and the file store's own comment is that a tombstone which vanishes "resurrects the tenant on the next
// bundle". Losing 26 of them un-deletes 26 organizations across the fleet.
//
// Control-plane HA is a state-sharing problem first, so this move is on the path to every HA deployment. It has
// to be safe to leave in the deployment file, which means: carry everything, never overwrite what the shared
// store already holds, and refuse rather than start empty when the named source cannot be read.
func TestTheTenantCatalogIsCarriedIntoPostgresWithItsTombstones(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() {
		for _, stmt := range []string{
			"DROP TABLE IF EXISTS admin_tenant_models",
			"DROP TABLE IF EXISTS admin_tenant_model_deletions",
			"DROP TABLE IF EXISTS admin_tenant_model_purge_orders",
			// A brand-new database has no ledger yet, and a fixture reset must not fail for being first.
			"DO $$ BEGIN IF to_regclass('schema_migrations') IS NOT NULL THEN DELETE FROM schema_migrations WHERE version IN ('023','024','038','039','040','041'); END IF; END $$",
		} {
			_, _ = db.ExecContext(context.Background(), stmt)
		}
		_ = db.Close()
	})
	for _, stmt := range []string{
		"DROP TABLE IF EXISTS admin_tenant_models",
		"DROP TABLE IF EXISTS admin_tenant_model_deletions",
		"DROP TABLE IF EXISTS admin_tenant_model_purge_orders",
		// A brand-new database has no ledger yet, and a fixture reset must not fail for being first.
		"DO $$ BEGIN IF to_regclass('schema_migrations') IS NOT NULL THEN DELETE FROM schema_migrations WHERE version IN ('023','024','038','039','040','041'); END IF; END $$",
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("reset the fixture (%s): %v", stmt, err)
		}
	}

	// A file snapshot in the shape the file store actually writes, including an organization that was DELETED
	// and one that was ordered ERASED.
	dir := t.TempDir()
	source := filepath.Join(dir, "tenant_models.json")
	snapshot := adminTenantModelSnapshot{
		Tenants: map[string]adminTenantModel{
			"tenant_lab_001":   {TenantID: "tenant_lab_001", DisplayName: "Reference Lab", Status: "active"},
			"tenant_northwind": {TenantID: "tenant_northwind", DisplayName: "Northwind", Status: "active", OperatorManaged: true, Timezone: "Asia/Tokyo"},
		},
		Deleted:     map[string]string{"tenant_gone": "2026-08-01T00:00:00Z"},
		PurgeOrders: map[string]string{"tenant_terminated": "2026-08-02T00:00:00Z"},
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal the snapshot: %v", err)
	}
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatalf("write the snapshot: %v", err)
	}

	bundle := model.PolicyBundle{TenantID: "tenant_lab_001", ID: "bundle_lab", Version: "v1"}
	now := time.Date(2026, 8, 18, 3, 0, 0, 0, time.UTC)
	auth := postgresAdminAuthStore{DB: db}
	migrations := filepath.Join("..", "..", "migrations")

	store, err := setupPostgresAdminTenantModelStore(ctx, auth, migrations, true, bundle, "", source, now)
	if err != nil {
		t.Fatalf("setup with import: %v", err)
	}

	tenants, err := store.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byID := map[string]adminTenantModel{}
	for _, tenant := range tenants {
		byID[tenant.TenantID] = tenant
	}
	if _, ok := byID["tenant_northwind"]; !ok {
		t.Fatalf("the customer's organization was not carried across — this is the measured defect: %v", tenants)
	}
	// The whole row travels, not just the id: the delegation is what decides whether the operator may act
	// inside this organization at all, and it fails CLOSED when dropped.
	if !byID["tenant_northwind"].OperatorManaged {
		t.Fatal("the standing delegation did not survive the move, so the operator silently loses access to the organization that granted it")
	}
	if byID["tenant_northwind"].Timezone != "Asia/Tokyo" {
		t.Fatalf("the organization's timezone did not survive: %q", byID["tenant_northwind"].Timezone)
	}

	// ★ The tombstone. Without it the deleted organization comes back on the next bundle.
	deletions := store.DeletedTenants()
	if len(deletions) != 1 || deletions[0].TenantID != "tenant_gone" {
		t.Fatalf("the deletion tombstone was not carried, so the organization un-deletes on the next bundle: %v", deletions)
	}
	// And the standing erasure order, which is the only thing that ever tells a node to erase.
	orders := store.PurgeOrders()
	if len(orders) != 1 || orders[0].TenantID != "tenant_terminated" {
		t.Fatalf("the erasure order was not carried: %v", orders)
	}

	// ★★ A SECOND BOOT MUST NOT LET A STALE FILE OVERWRITE SHARED STATE. The organization is renamed in
	// Postgres (as an administrator would), the file still says the old name, and the file must lose.
	renamed := byID["tenant_northwind"]
	renamed.DisplayName = "Northwind Traders KK"
	if _, err := store.Put(ctx, renamed, now); err != nil {
		t.Fatalf("rename in the shared store: %v", err)
	}
	second, err := setupPostgresAdminTenantModelStore(ctx, auth, migrations, true, bundle, "", source, now)
	if err != nil {
		t.Fatalf("second setup: %v", err)
	}
	after, err := second.Get(ctx, "tenant_northwind")
	if err != nil {
		t.Fatalf("get after the second boot: %v", err)
	}
	if after.DisplayName != "Northwind Traders KK" {
		t.Fatalf("a stale file overwrote the shared store on the second boot: %q", after.DisplayName)
	}

	// ★★ AND A ROW THAT WAS ALREADY THERE CAN STILL BE MISSING SETTINGS (2026-08-18, measured on the first real
	// move). The reference control plane held ONE row — a seed from an earlier boot carrying nothing but the id
	// — and the additive rule left it exactly as it was, so that organization's timezone silently did not
	// survive. An EMPTY field holds nothing: filling one takes nothing from anybody, and dropping a setting an
	// administrator chose is the failure this path exists to prevent.
	for _, stmt := range []string{
		"DROP TABLE IF EXISTS admin_tenant_models",
		"DROP TABLE IF EXISTS admin_tenant_model_deletions",
		"DROP TABLE IF EXISTS admin_tenant_model_purge_orders",
		// A brand-new database has no ledger yet, and a fixture reset must not fail for being first.
		"DO $$ BEGIN IF to_regclass('schema_migrations') IS NOT NULL THEN DELETE FROM schema_migrations WHERE version IN ('023','024','038','039','040','041'); END IF; END $$",
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("reset for the fill case: %v", err)
		}
	}
	// A seeded row: the id, and nothing an administrator chose.
	seeded, err := setupPostgresAdminTenantModelStore(ctx, auth, migrations, true, bundle, "", "", now)
	if err != nil {
		t.Fatalf("seed-only setup: %v", err)
	}
	if before, err := seeded.Get(ctx, "tenant_lab_001"); err != nil {
		t.Fatalf("read the seeded row: %v", err)
	} else if strings.TrimSpace(before.Timezone) != "" {
		t.Fatalf("the seeded row already carries a timezone, so this case measures nothing: %q", before.Timezone)
	}
	// The file says this organization chose Asia/Tokyo and a display name.
	fillSnapshot := adminTenantModelSnapshot{Tenants: map[string]adminTenantModel{
		"tenant_lab_001": {TenantID: "tenant_lab_001", DisplayName: "Reference Lab", Status: "active", Timezone: "Asia/Tokyo", Plan: "enterprise"},
	}}
	filledRaw, err := json.Marshal(fillSnapshot)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	fillSource := filepath.Join(dir, "with_settings.json")
	if err := os.WriteFile(fillSource, filledRaw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	merged, err := setupPostgresAdminTenantModelStore(ctx, auth, migrations, true, bundle, "", fillSource, now)
	if err != nil {
		t.Fatalf("setup with the fill source: %v", err)
	}
	after, err2 := merged.Get(ctx, "tenant_lab_001")
	err = err2
	if err != nil {
		t.Fatalf("read after the fill: %v", err)
	}
	if after.Timezone != "Asia/Tokyo" {
		t.Fatalf("the organization's timezone was dropped by the move: %q", after.Timezone)
	}
	if after.DisplayName != "Reference Lab" {
		t.Fatalf("a display name that was still the id was not filled: %q", after.DisplayName)
	}
	if after.Plan != "enterprise" {
		t.Fatalf("plan was not filled: %q", after.Plan)
	}
	// ★ THE CONTROL: a field the shared store ALREADY holds must not move, or "additive" is a fiction.
	renamedInShared := after
	renamedInShared.DisplayName = "Renamed In The Shared Store"
	renamedInShared.Timezone = "Europe/Berlin"
	if _, err := merged.Put(ctx, renamedInShared, now); err != nil {
		t.Fatalf("author in the shared store: %v", err)
	}
	third, err := setupPostgresAdminTenantModelStore(ctx, auth, migrations, true, bundle, "", fillSource, now)
	if err != nil {
		t.Fatalf("third setup: %v", err)
	}
	kept, err := third.Get(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("read after the third: %v", err)
	}
	if kept.DisplayName != "Renamed In The Shared Store" || kept.Timezone != "Europe/Berlin" {
		t.Fatalf("the file overwrote what the shared store already held: name=%q tz=%q", kept.DisplayName, kept.Timezone)
	}

	// ★ A NAMED SOURCE THAT CANNOT BE READ IS A REFUSAL. Starting with an empty catalog looks exactly like a
	// clean move, which is the failure this whole path exists to prevent.
	if _, err := setupPostgresAdminTenantModelStore(ctx, auth, migrations, true, bundle, "", dir, now); err == nil {
		t.Fatal("an unreadable source was accepted, so a control plane can start having quietly forgotten every deletion it carried")
	}

	// ★ THE CONTROL: with NO import named, the move carries nothing — which is exactly the behaviour that was
	// measured as the defect. If this passed too, the test above would prove nothing about the import.
	for _, stmt := range []string{
		"DROP TABLE IF EXISTS admin_tenant_models",
		"DROP TABLE IF EXISTS admin_tenant_model_deletions",
		"DROP TABLE IF EXISTS admin_tenant_model_purge_orders",
		// A brand-new database has no ledger yet, and a fixture reset must not fail for being first.
		"DO $$ BEGIN IF to_regclass('schema_migrations') IS NOT NULL THEN DELETE FROM schema_migrations WHERE version IN ('023','024','038','039','040','041'); END IF; END $$",
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("reset for the control: %v", err)
		}
	}
	control, err := setupPostgresAdminTenantModelStore(ctx, auth, migrations, true, bundle, "", "", now)
	if err != nil {
		t.Fatalf("control setup: %v", err)
	}
	controlTenants, err := control.List(ctx)
	if err != nil {
		t.Fatalf("control list: %v", err)
	}
	for _, tenant := range controlTenants {
		if tenant.TenantID == "tenant_northwind" {
			t.Fatal("the control found the customer's organization without an import, so the import is not what carried it")
		}
	}
	if len(control.DeletedTenants()) != 0 {
		t.Fatal("the control found tombstones without an import")
	}
}
