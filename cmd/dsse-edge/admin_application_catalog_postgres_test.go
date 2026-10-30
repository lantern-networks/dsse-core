package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
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

func TestPostgresApplicationCatalogLegacyImportMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "057_application_catalog_import.sql"))
	if err != nil {
		t.Fatal(err)
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresApplicationCatalogImportSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(string(data))
	if got != want {
		t.Fatalf("legacy import migration SQL does not match schema helper\nmigration: %s\nhelper: %s", got, want)
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

// TestPostgresApplicationCatalogMigrationVersions confirms both the catalog and its durable import ledger apply.
func TestPostgresApplicationCatalogMigrationVersions(t *testing.T) {
	versions := postgresApplicationCatalogMigrationVersions()
	if len(versions) != 2 || versions[0] != postgresMigrationApplicationCatalog || versions[1] != postgresMigrationApplicationCatalogImport {
		t.Fatalf("application catalog migration versions = %#v, want [%s, %s]", versions, postgresMigrationApplicationCatalog, postgresMigrationApplicationCatalogImport)
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

func TestPostgresApplicationCatalogListAllBeyondFirstThousand(t *testing.T) {
	// This bulk test creates/drops the catalog table, so it needs its own
	// disposable database rather than the shared Postgres E2E database.
	dsn := os.Getenv("DSSE_CATALOG_LISTALL_E2E_DSN")
	if dsn == "" {
		t.Skip("DSSE_CATALOG_LISTALL_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var databaseName string
	if err := db.QueryRowContext(ctx, "SELECT current_database()").Scan(&databaseName); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(databaseName, "review_") && !strings.HasPrefix(databaseName, "test_") {
		t.Fatalf("full-catalog E2E requires a disposable review_/test_ database, got %q", databaseName)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS application_catalog"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS application_catalog") }()
	for _, statement := range postgresApplicationCatalogSchemaSQL() {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	const tenant = "tenant_catalog_complete"
	if _, err := db.ExecContext(ctx, `INSERT INTO application_catalog
		(tenant_id, application_id, name, application_type, status, updated_at)
		SELECT $1, 'a' || lpad(g::text, 4, '0'), 'ordinary', 'private_app', 'active', now()
		FROM generate_series(0, 999) AS g`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO application_catalog
		(tenant_id, application_id, name, application_type, status, published, destination, destination_port, publish_protocol, updated_at)
		VALUES ($1, 'zzzz', 'disabled', 'private_app', 'disabled', true, 'disabled.example.test', 443, 'web', now())`, tenant); err != nil {
		t.Fatal(err)
	}
	store := &postgresApplicationCatalogStore{db: db}
	bounded, err := store.List(ctx, tenant, appcatalog.ListOptions{ApplicationType: "private_app", Limit: 1000})
	if err != nil || bounded.Count != 1001 || len(bounded.Applications) != 1000 {
		t.Fatalf("bounded List contract changed: count=%d len=%d err=%v", bounded.Count, len(bounded.Applications), err)
	}
	all, err := store.ListAll(ctx, tenant, appcatalog.ListAllOptions{ApplicationType: "private_app"})
	if err != nil || len(all) != 1001 || all[len(all)-1].ApplicationID != "zzzz" {
		t.Fatalf("trusted full list incomplete: len=%d err=%v", len(all), err)
	}
	other, err := store.ListAll(ctx, "other_tenant", appcatalog.ListAllOptions{})
	if err != nil || len(other) != 0 {
		t.Fatalf("trusted full list crossed tenant boundary: len=%d err=%v", len(other), err)
	}
	base := map[string]edgeplane.ApplicationRouteProfile{"zzzz": {Destination: "old-enabled.example.test"}}
	routes, err := edgeplane.RouteProfilesWithPublishedCatalog(ctx, base, store, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := routes["zzzz"]; ok {
		t.Fatal("late disabled Postgres row left base route enabled")
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

func TestPostgresApplicationCatalogImportsAuthoredLocalRowsWithoutReplacingNewerSharedRows(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	base, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("application_import_%d", time.Now().UnixNano())
	if _, err := base.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer base.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pgAuth := postgresAdminAuthStore{DB: db}
	// The same selected component migrations the generated CP runs must create
	// both durable tables on a fresh database, before any local-file import.
	if _, err := setupPostgresApplicationCatalogStore(ctx, pgAuth, filepath.Join("..", "..", "migrations"), true, nil); err != nil {
		t.Fatalf("fresh component migrations: %v", err)
	}
	const operator, customer = "tenant_operator", "tenant_customer"
	seed := map[string]edgeplane.ApplicationRouteProfile{"app_seed": {}}
	file := filepath.Join(t.TempDir(), "application_catalog.json")
	local, err := setupApplicationCatalogStore(ctx, file, newAdminAuthStore(), "", false, operator, seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ tenant, id, name string }{
		{operator, "app_owned", "stale local copy"},
		{operator, "app_operator_second", "second operator app"},
		{customer, "app_customer", "customer private app"},
		{customer, "app_customer_second", "second customer app"},
	} {
		if _, err := local.Upsert(ctx, appcatalog.Entry{ApplicationID: row.id, Name: row.name, ApplicationType: "private_app", Status: "active"}, row.tenant, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	legacyBytes, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := setupPostgresApplicationCatalogStore(ctx, pgAuth, "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := shared.Upsert(ctx, appcatalog.Entry{ApplicationID: "app_owned", Name: "newer shared copy", ApplicationType: "private_app", Status: "active"}, operator, time.Now()); err != nil {
		t.Fatal(err)
	}
	seedOnlyFile := filepath.Join(t.TempDir(), "application_catalog.json")
	if err := os.WriteFile(seedOnlyFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := setupApplicationCatalogStore(ctx, "postgres+import:"+seedOnlyFile, pgAuth, "", false, operator, seed, nil); err != nil {
		t.Fatalf("seed-only old CP startup: %v", err)
	}
	if _, err := os.Stat(seedOnlyFile); !os.IsNotExist(err) {
		t.Fatalf("seed-only old file was not retired: %v", err)
	}
	var seals int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM application_catalog_legacy_import_state").Scan(&seals); err != nil || seals != 0 {
		t.Fatalf("seed-only old CP sealed import before authored CP: seals=%d err=%v", seals, err)
	}
	// CP A and C have no local authored file. They start before B and must
	// observe B's eventual import through the same shared database.
	absentDir := t.TempDir()
	cpA, err := setupApplicationCatalogStore(ctx, "postgres+import:"+filepath.Join(absentDir, "a.json"), pgAuth, "", false, operator, seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	cpC, err := setupApplicationCatalogStore(ctx, "postgres+import:"+filepath.Join(absentDir, "c.json"), pgAuth, "", false, operator, seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected := "postgres+import:" + file
	var cpB appcatalog.RuntimeStore
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			// Simulate restoring the stale local file from a node snapshot.
			if err := os.WriteFile(file, legacyBytes, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		migrated, err := setupApplicationCatalogStore(ctx, selected, pgAuth, "", false, operator, seed, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Fatalf("legacy tenant data remained outside purge after CP startup: %v", err)
		}
		cpB = migrated
		if got, found, err := migrated.Get(ctx, operator, "app_owned"); err != nil || !found || got.Name != "newer shared copy" {
			t.Fatalf("newer shared row was replaced: %+v, found=%v, err=%v", got, found, err)
		}
		if got, found, err := migrated.Get(ctx, customer, "app_customer"); err != nil || !found || got.Name != "customer private app" {
			t.Fatalf("customer authored row was not imported: %+v, found=%v, err=%v", got, found, err)
		}
		if _, found, err := migrated.Get(ctx, operator, "app_seed"); err != nil || !found {
			t.Fatalf("configuration seed disappeared: found=%v, err=%v", found, err)
		}
		var rows int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM application_catalog").Scan(&rows); err != nil || rows != 4 {
			t.Fatalf("imported authored row count=%d, err=%v; seed must remain config-derived", rows, err)
		}
	}
	edgeCatalog := appcatalog.NewStore()
	var before *applicationCatalogBundle
	var generation uint64
	var bundleState *applicationBundleState
	for _, cp := range []appcatalog.RuntimeStore{cpA, cpB, cpC} {
		bundleState = &applicationBundleState{}
		before, generation, err = bundleState.read(ctx, cp)
		if err != nil || before == nil || !before.Complete {
			t.Fatalf("shared catalog did not survive CP leader switch into a complete Edge bundle: generation=%d, err=%v", generation, err)
		}
		if err := applyApplicationBundle(edgeCatalog, before); err != nil {
			t.Fatal(err)
		}
		for _, row := range []struct{ tenant, id string }{
			{operator, "app_owned"}, {operator, "app_operator_second"},
			{customer, "app_customer"}, {customer, "app_customer_second"},
		} {
			if _, found, err := edgeCatalog.Get(ctx, row.tenant, row.id); err != nil || !found {
				t.Fatalf("CP failover dropped %s/%s from Edge: found=%v, err=%v", row.tenant, row.id, found, err)
			}
		}
	}
	if _, found, err := edgeCatalog.Get(ctx, customer, "app_customer"); err != nil || !found {
		t.Fatalf("imported customer route did not reach Edge: found=%v, err=%v", found, err)
	}
	if err := shared.Delete(ctx, customer, "app_customer"); err != nil {
		t.Fatal(err)
	}
	// Tenant erasure removes the tenant-keyed import markers. The DB-wide
	// source seal must still prevent a restored old-node JSON from recreating
	// the erased application during a later CP restart.
	if _, err := db.ExecContext(ctx, "DELETE FROM application_catalog_legacy_imports WHERE tenant_id = $1", customer); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, legacyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	afterDeletion, err := setupApplicationCatalogStore(ctx, selected, pgAuth, "", false, operator, seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("stale restored source was not retired before CP became ready: %v", err)
	}
	if _, found, err := afterDeletion.Get(ctx, customer, "app_customer"); err != nil || found {
		t.Fatalf("stale local file resurrected intentionally deleted customer app: found=%v, err=%v", found, err)
	}
	after, nextGeneration, err := bundleState.read(ctx, afterDeletion)
	if err != nil || nextGeneration <= generation {
		t.Fatalf("shared deletion did not advance Edge bundle: %d -> %d, err=%v", generation, nextGeneration, err)
	}
	if err := applyApplicationBundle(edgeCatalog, after); err != nil {
		t.Fatal(err)
	}
	if _, found, err := edgeCatalog.Get(ctx, customer, "app_customer"); err != nil || found {
		t.Fatalf("deleted customer route remained on Edge: found=%v, err=%v", found, err)
	}
	var markers int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM application_catalog_legacy_imports").Scan(&markers); err != nil || markers != 2 {
		t.Fatalf("remaining operator import marker count=%d, err=%v", markers, err)
	}
	if err := os.WriteFile(file, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := setupApplicationCatalogStore(ctx, selected, pgAuth, "", false, operator, seed, nil); err == nil {
		t.Fatal("unreadable migration source was accepted as an empty catalog")
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE application_catalog_legacy_imports"); err != nil {
		t.Fatal(err)
	}
	if _, err := setupApplicationCatalogStore(ctx, selected, pgAuth, "", true, operator, seed, nil); err == nil || !strings.Contains(err.Error(), "predates the durable import marker") {
		t.Fatalf("pre-marker shared catalog with ambiguous import was not refused: %v", err)
	}
}
