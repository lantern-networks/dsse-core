package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"

	_ "github.com/lib/pq"
)

// TestPostgresApplicationCatalogMigrationMatchesSchemaSQL keeps the on-disk migration in lockstep with the in-code
// schema contract, the same fidelity guard the tenant model / site stores use.
func TestPostgresApplicationCatalogMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "026_application_catalog.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresApplicationCatalogSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(string(data))
	if got != want {
		t.Fatalf("application catalog migration SQL does not match schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
}

// TestPostgresApplicationCatalogSchemaSecurityContracts pins the tenant-scoping invariant (composite PK on
// tenant_id) and the full-fidelity columns that must survive a round-trip.
func TestPostgresApplicationCatalogSchemaSecurityContracts(t *testing.T) {
	sqlText := strings.Join(postgresApplicationCatalogSchemaSQL(), "\n")
	for _, want := range []string{
		"PRIMARY KEY (tenant_id, application_id)",
		"tenant_id text NOT NULL",
		"application_id text NOT NULL",
		"tags jsonb NOT NULL DEFAULT '[]'",
		"published boolean NOT NULL DEFAULT false",
		"destination_port integer NOT NULL DEFAULT 0",
		"updated_at timestamptz NOT NULL",
	} {
		if !strings.Contains(sqlText, want) {
			t.Fatalf("application catalog schema SQL missing %q:\n%s", want, sqlText)
		}
	}
}

// TestPostgresApplicationCatalogMigrationVersions confirms the component migration set is the single 026 migration.
func TestPostgresApplicationCatalogMigrationVersions(t *testing.T) {
	versions := postgresApplicationCatalogMigrationVersions()
	if len(versions) != 1 || versions[0] != postgresMigrationApplicationCatalog {
		t.Fatalf("application catalog migration versions = %#v, want [%s]", versions, postgresMigrationApplicationCatalog)
	}
}

// TestSetupPostgresApplicationCatalogStoreRequiresPostgresAdminAuth confirms the backend refuses to start (rather
// than silently degrading) when the admin auth store is not Postgres — there is no connection to reuse.
func TestSetupPostgresApplicationCatalogStoreRequiresPostgresAdminAuth(t *testing.T) {
	_, err := setupPostgresApplicationCatalogStore(context.Background(), newAdminAuthStore(), "migrations", false, nil)
	if err == nil || !strings.Contains(err.Error(), "admin-auth-store=postgres") {
		t.Fatalf("setup error = %v, want admin-auth-store=postgres requirement", err)
	}
}

// TestSetupApplicationCatalogStorePostgresGuard confirms the combined selector also fails fast when "postgres" is
// requested without a Postgres admin auth store (the path main takes).
func TestSetupApplicationCatalogStorePostgresGuard(t *testing.T) {
	_, err := setupApplicationCatalogStore(context.Background(), "postgres", newAdminAuthStore(), "migrations", false, "tenant_lab_001", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "admin-auth-store=postgres") {
		t.Fatalf("setup error = %v, want admin-auth-store=postgres requirement", err)
	}
}

// TestSetupApplicationCatalogStoreFileUnchanged confirms the lab default path (empty + file) is unchanged: the
// config seed is present and operator-authored entries persist to the file and survive a "restart" (new store over
// the same file), with authored entries overlaying the seed. This is the additive guarantee — wiring the Postgres
// option must not change file/in-memory behavior.
func TestSetupApplicationCatalogStoreFileUnchanged(t *testing.T) {
	ctx := context.Background()
	tenantID := "tenant_lab_001"
	routeProfiles := map[string]edgeplane.ApplicationRouteProfile{"app_seed_https": {}}
	now := time.Date(2026, 6, 28, 2, 0, 0, 0, time.UTC)

	// Empty path = in-memory only; seed is present.
	mem, err := setupApplicationCatalogStore(ctx, "", newAdminAuthStore(), "", false, tenantID, routeProfiles, nil)
	if err != nil {
		t.Fatalf("setup in-memory: %v", err)
	}
	if _, ok, gerr := mem.Get(ctx, tenantID, "app_seed_https"); gerr != nil || !ok {
		t.Fatalf("seed entry missing in in-memory store: ok=%v err=%v", ok, gerr)
	}

	// File path = durability of authored entries across a restart.
	path := filepath.Join(t.TempDir(), "catalog.json")
	first, err := setupApplicationCatalogStore(ctx, path, newAdminAuthStore(), "", false, tenantID, routeProfiles, nil)
	if err != nil {
		t.Fatalf("setup file: %v", err)
	}
	if _, err := first.Upsert(ctx, appcatalog.Entry{ApplicationID: "app_authored_001", Name: "Authored", ApplicationType: "private_app"}, tenantID, now); err != nil {
		t.Fatalf("upsert authored: %v", err)
	}
	// New store over the same file = "restart": seed re-derived, authored overlay reloaded.
	second, err := setupApplicationCatalogStore(ctx, path, newAdminAuthStore(), "", false, tenantID, routeProfiles, nil)
	if err != nil {
		t.Fatalf("setup file reload: %v", err)
	}
	if _, ok, gerr := second.Get(ctx, tenantID, "app_authored_001"); gerr != nil || !ok {
		t.Fatalf("authored entry did not survive restart: ok=%v err=%v", ok, gerr)
	}
	if _, ok, gerr := second.Get(ctx, tenantID, "app_seed_https"); gerr != nil || !ok {
		t.Fatalf("seed entry missing after restart: ok=%v err=%v", ok, gerr)
	}
}

// TestPostgresApplicationCatalogStoreE2E exercises the full appcatalog.RuntimeStore contract against a real
// Postgres: seed/authored merge, authored-wins overlay, CRUD round-trip of every field, list filtering, restart
// durability, and tenant scoping (a tenant cannot see another tenant's authored entries). Env-gated and skipped
// when POSTGRES_QUEUE_E2E_DSN is unset, matching the other postgres E2E tests.
func TestPostgresApplicationCatalogStoreE2E(t *testing.T) {
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
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS application_catalog")
		_ = db.Close()
	})
	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS application_catalog"); err != nil {
		t.Fatalf("drop pre-existing table: %v", err)
	}

	tenantA := "tenant_lab_001"
	tenantB := "tenant_other_001"
	now := time.Date(2026, 6, 28, 3, 0, 0, 0, time.UTC)

	// Seed has a config entry for tenant A only.
	seed := map[string]map[string]appcatalog.Entry{
		tenantA: {"app_seed_https": appcatalog.CopyEntry(appcatalog.Entry{ApplicationID: "app_seed_https", TenantID: tenantA, Name: "Seed HTTPS", ApplicationType: "private_app", Status: "active"})},
	}

	store, err := setupPostgresApplicationCatalogStore(ctx, postgresAdminAuthStore{DB: db}, filepath.Join("..", "..", "migrations"), true, seed)
	if err != nil {
		t.Fatalf("setup returned error: %v", err)
	}

	// Seed entry is visible without any DB row.
	if seedEntry, ok, gerr := store.Get(ctx, tenantA, "app_seed_https"); gerr != nil || !ok || seedEntry.Name != "Seed HTTPS" {
		t.Fatalf("seed get = %#v ok=%v err=%v, want Seed HTTPS", seedEntry, ok, gerr)
	}

	// Authored upsert with every additive field populated.
	authored := appcatalog.Entry{
		ApplicationID:    "app_authored_001",
		Name:             "Authored Private App",
		ApplicationType:  "private_app",
		ServiceFamily:    "ssh",
		Protocol:         "tcp",
		Tags:             []string{"prod", "tier0"},
		Status:           "active",
		Destination:      "10.0.0.5",
		DestinationPort:  22,
		PublishProtocol:  "tcp",
		ConnectorGroupID: "cgrp_lab_001",
		Published:        true,
		RoutingNamespace: "site_a",
	}
	created, err := store.Upsert(ctx, authored, tenantA, now)
	if err != nil {
		t.Fatalf("upsert authored: %v", err)
	}
	if created.UpdatedAt == nil || created.DestinationRole != "ssh_server" {
		t.Fatalf("normalized authored entry = %#v, want updated_at + ssh_server role", created)
	}

	// Round-trip: every field survives the DB.
	got, ok, err := store.Get(ctx, tenantA, "app_authored_001")
	if err != nil || !ok {
		t.Fatalf("get authored: ok=%v err=%v", ok, err)
	}
	if got.Destination != "10.0.0.5" || got.DestinationPort != 22 || got.PublishProtocol != "tcp" ||
		got.ConnectorGroupID != "cgrp_lab_001" || !got.Published || got.RoutingNamespace != "site_a" ||
		len(got.Tags) != 2 || got.Tags[0] != "prod" {
		t.Fatalf("authored round-trip lost fields: %#v", got)
	}

	// Authored-wins overlay: re-author the seed id; the DB row must override the seed at read time.
	if _, err := store.Upsert(ctx, appcatalog.Entry{ApplicationID: "app_seed_https", Name: "Overridden", ApplicationType: "private_app", Status: "disabled"}, tenantA, now.Add(time.Minute)); err != nil {
		t.Fatalf("override seed: %v", err)
	}
	overridden, _, err := store.Get(ctx, tenantA, "app_seed_https")
	if err != nil {
		t.Fatalf("get overridden: %v", err)
	}
	if overridden.Name != "Overridden" || overridden.Status != "disabled" {
		t.Fatalf("authored did not override seed: %#v", overridden)
	}

	// List merges seed + authored for tenant A (seed override + new authored = 2).
	listA, err := store.List(ctx, tenantA, appcatalog.ListOptions{})
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	if listA.Count != 2 {
		t.Fatalf("list A count = %d, want 2 (overridden seed + authored)", listA.Count)
	}

	// List filter by status returns only matching entries.
	active, err := store.List(ctx, tenantA, appcatalog.ListOptions{Status: "active"})
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if active.Count != 1 || active.Applications[0].ApplicationID != "app_authored_001" {
		t.Fatalf("active filter = %#v, want only app_authored_001", active.Applications)
	}

	// Tenant scoping: tenant B has no seed and no authored rows; it cannot see tenant A's entries.
	listB, err := store.List(ctx, tenantB, appcatalog.ListOptions{})
	if err != nil {
		t.Fatalf("list B: %v", err)
	}
	if listB.Count != 0 {
		t.Fatalf("tenant B list count = %d, want 0 (cross-tenant isolation)", listB.Count)
	}
	if _, ok, gerr := store.Get(ctx, tenantB, "app_authored_001"); gerr != nil || ok {
		t.Fatalf("tenant B could see tenant A authored entry: ok=%v err=%v", ok, gerr)
	}

	// Restart durability: a fresh store over the same DB still sees the authored entry.
	restarted, err := setupPostgresApplicationCatalogStore(ctx, postgresAdminAuthStore{DB: db}, filepath.Join("..", "..", "migrations"), true, seed)
	if err != nil {
		t.Fatalf("restart setup: %v", err)
	}
	if _, ok, gerr := restarted.Get(ctx, tenantA, "app_authored_001"); gerr != nil || !ok {
		t.Fatalf("authored entry did not survive restart: ok=%v err=%v", ok, gerr)
	}
	// Another CP writes through the shared database; the publisher must observe
	// its creation, update and last deletion without using an in-process write count.
	state := &applicationBundleState{}
	_, before, err := state.read(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	other := publishedAppForDistribution(tenantB, "10.70.1.1")
	if _, err := restarted.Upsert(ctx, other, tenantB, now); err != nil {
		t.Fatal(err)
	}
	section, added, err := state.read(ctx, store)
	if err != nil || added <= before || section.Entries[tenantB][other.ApplicationID].Destination != "10.70.1.1" {
		t.Fatalf("shared snapshot did not see addition: %v", err)
	}
	other.Destination = "10.70.1.2"
	if _, err := restarted.Upsert(ctx, other, tenantB, now); err != nil {
		t.Fatal(err)
	}
	section, changed, err := state.read(ctx, store)
	if err != nil || changed <= added || section.Entries[tenantB][other.ApplicationID].Destination != "10.70.1.2" {
		t.Fatalf("shared snapshot did not see update: %v", err)
	}
	if err := restarted.Delete(ctx, tenantB, other.ApplicationID); err != nil {
		t.Fatal(err)
	}
	section, removed, err := state.read(ctx, store)
	if err != nil || removed <= changed || len(section.Entries[tenantB]) != 0 || len(section.Entries[tenantA]) != 2 {
		t.Fatalf("shared snapshot did not carry tenant-isolated deletion: %v", err)
	}
}
