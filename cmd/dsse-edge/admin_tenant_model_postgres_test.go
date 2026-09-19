package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"

	"database/sql"

	_ "github.com/lib/pq"
)

// TestPostgresAdminTenantModelMigrationMatchesSchemaSQL keeps the on-disk migration in lockstep with the in-code
// schema contract, the same fidelity guard the admin auth store uses.
func TestPostgresAdminTenantModelMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "023_admin_tenant_models.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresAdminTenantModelSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(string(data))
	if got != want {
		t.Fatalf("tenant model migration SQL does not match schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
}

// TestPostgresAdminTenantModelSchemaSecurityContracts pins the tenant-scoping and lifecycle invariants.
func TestPostgresAdminTenantModelSchemaSecurityContracts(t *testing.T) {
	sqlText := strings.Join(postgresAdminTenantModelSchemaSQL(), "\n")
	for _, want := range []string{
		"PRIMARY KEY (tenant_id)",
		"CHECK (status IN ('active', 'suspended', 'archived'))",
		"display_name text NOT NULL",
		"created_at timestamptz NOT NULL",
		"updated_at timestamptz NOT NULL",
	} {
		if !strings.Contains(sqlText, want) {
			t.Fatalf("tenant model schema SQL missing %q:\n%s", want, sqlText)
		}
	}
}

// TestSetupPostgresAdminTenantModelStoreRequiresPostgresAdminAuth confirms the backend refuses to start (rather
// than silently degrading) when the admin auth store is not Postgres — there is no connection to reuse.
func TestSetupPostgresAdminTenantModelStoreRequiresPostgresAdminAuth(t *testing.T) {
	_, err := setupPostgresAdminTenantModelStore(context.Background(), newAdminAuthStore(), "migrations", false, model.PolicyBundle{TenantID: "tenant_lab_001"}, "", "", time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "admin-auth-store=postgres") {
		t.Fatalf("setup error = %v, want admin-auth-store=postgres requirement", err)
	}
}

// TestPostgresAdminTenantModelStoreE2E exercises the full adminTenantModelAdminStore contract against a real
// Postgres (seed-on-boot, self Get/Update, cross-tenant Put/List/Delete, provenance preservation, tenant
// scoping). Env-gated and skipped when POSTGRES_QUEUE_E2E_DSN is unset, matching the other postgres E2E tests.
func TestPostgresAdminTenantModelStoreE2E(t *testing.T) {
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
		// ★ THE LEDGER GOES WITH THE TABLES (2026-08-17). Dropping the tables while schema_migrations still
		// says 023/024/038/039 are applied makes the NEXT run skip the migrations and die on "relation
		// admin_tenant_models does not exist" — so this test passed once per database and then failed forever,
		// which reads as a broken change rather than a dirty fixture. Measured by running it twice.
		for _, stmt := range []string{
			"DROP TABLE IF EXISTS admin_tenant_models",
			"DROP TABLE IF EXISTS admin_tenant_model_deletions",
			// ★ AND THE LIST HAS TO GROW WITH THE MIGRATIONS, WHICH IT HAD ALREADY STOPPED DOING (2026-08-18).
			// 040 and 041 were added without being added here, which is the exact failure the comment above
			// describes: the tables go, the ledger says they are applied, and the next run dies. Found by
			// adding 041 and reading the cleanup rather than by the second run.
			"DROP TABLE IF EXISTS admin_tenant_model_purge_orders",
			"DELETE FROM schema_migrations WHERE version IN ('023', '024', '038', '039', '040', '041', '044')",
		} {
			_, _ = db.ExecContext(context.Background(), stmt)
		}
		_ = db.Close()
	})
	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS admin_tenant_models"); err != nil {
		t.Fatalf("drop pre-existing table: %v", err)
	}

	bundle := model.PolicyBundle{TenantID: "tenant_lab_001", ID: "bundle_lab", Version: "v1", Metadata: map[string]any{"a": 1, "b": 2}}
	now := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)

	store, err := setupPostgresAdminTenantModelStore(ctx, postgresAdminAuthStore{DB: db}, filepath.Join("..", "..", "migrations"), true, bundle, "", "", now)
	if err != nil {
		t.Fatalf("setup returned error: %v", err)
	}

	// Seed-on-boot: the bundle tenant exists with metadata_key_count from the bundle.
	seeded, err := store.Get(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("get seeded: %v", err)
	}
	if seeded.Status != "active" || seeded.MetadataKeyCount != 2 || seeded.PolicyBundleID != "bundle_lab" {
		t.Fatalf("seeded tenant = %#v, want active/2/bundle_lab", seeded)
	}

	// Cross-tenant Put with residency set.
	put, err := store.Put(ctx, adminTenantModel{TenantID: "tenant_acme_001", DisplayName: "Acme", Status: "suspended", Region: "region-a", AllowedRegions: []string{"region-a", "region-b"}, HomeRegion: "region-a", Plan: "enterprise"}, now)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if put.CreatedAt == nil || put.UpdatedAt == nil {
		t.Fatalf("put timestamps not set: %#v", put)
	}
	createdProvenance := *put.CreatedAt

	// List returns both tenants sorted by id.
	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 || list[0].TenantID != "tenant_acme_001" || list[1].TenantID != "tenant_lab_001" {
		t.Fatalf("list = %#v, want acme then lab", list)
	}
	if got := list[0]; len(got.AllowedRegions) != 2 || got.AllowedRegions[0] != "region-a" || got.Plan != "enterprise" {
		t.Fatalf("acme round-trip = %#v, want allowed_regions+plan preserved", got)
	}

	// Self-scoped Update preserves created_at provenance and advances updated_at.
	later := now.Add(time.Hour)
	updated, err := store.Update(ctx, adminTenantModel{TenantID: "tenant_acme_001", DisplayName: "Acme Corp", Status: "active"}, "tenant_acme_001", later)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.CreatedAt == nil || *updated.CreatedAt != createdProvenance {
		t.Fatalf("update created_at = %v, want preserved %s", updated.CreatedAt, createdProvenance)
	}
	if updated.UpdatedAt == nil || *updated.UpdatedAt == createdProvenance {
		t.Fatalf("update updated_at not advanced: %#v", updated)
	}
	if updated.DisplayName != "Acme Corp" || updated.Status != "active" {
		t.Fatalf("update did not apply: %#v", updated)
	}

	// ★★ THE STANDING DELEGATION ROUND-TRIPS (2026-08-17). It did not, and nothing here noticed: this test
	// round-tripped region, plan and allowed_regions — the fields somebody remembered to add — while the store
	// wrote no delegation column at all. So the operator envelope was inert in the Postgres backend, the one
	// the deployment documentation names for production, and the design document said the two backends behaved
	// identically. A customer could grant the operator its management, get a 200, and read false back.
	granted := "2026-06-28T02:00:00Z"
	by := "adm_operator"
	if _, err := store.Put(ctx, adminTenantModel{
		TenantID: "tenant_delegating_001", DisplayName: "Delegating", Status: "active",
		OperatorManaged:             true,
		OperatorDelegationChangedAt: &granted,
		OperatorDelegationChangedBy: &by,
	}, now); err != nil {
		t.Fatalf("put delegating tenant: %v", err)
	}
	back, err := store.Get(ctx, "tenant_delegating_001")
	if err != nil {
		t.Fatalf("get delegating tenant: %v", err)
	}
	if !back.OperatorManaged {
		t.Fatal("the standing delegation did not survive the store: an organization that granted it reads as " +
			"having refused, and the operator is locked out of every customer that said yes")
	}
	if back.OperatorDelegationChangedAt == nil || *back.OperatorDelegationChangedAt != granted {
		t.Fatalf("delegation changed_at = %v, want %s — without it the customer's screen cannot say when it moved",
			back.OperatorDelegationChangedAt, granted)
	}
	if back.OperatorDelegationChangedBy == nil || *back.OperatorDelegationChangedBy != by {
		t.Fatalf("delegation changed_by = %v, want %s", back.OperatorDelegationChangedBy, by)
	}
	// ★ THE REST OF THE ENVELOPE, AND THE CLOCK. operator_elevation_requires_approval is the one that fails
	// OPEN when it is dropped: an elevation is then created with ApprovalRequired=false, so the operator's
	// irreversible acts proceed without the approval the organization asked for. operator_elevations is the
	// customer's only record that the envelope was ever used.
	if _, err := store.Put(ctx, adminTenantModel{
		TenantID: "tenant_delegating_001", DisplayName: "Delegating", Status: "active",
		OperatorManaged:                   true,
		OperatorDelegationChangedAt:       &granted,
		OperatorDelegationChangedBy:       &by,
		OperatorElevationRequiresApproval: true,
		Timezone:                          "Asia/Tokyo",
		OperatorElevations: []operatorElevation{{
			ID: "elev_1", GrantedTo: "adm_operator", GrantedBy: "ops@lab.local",
			StartedAt: granted, ExpiresAt: "2026-06-28T02:30:00Z", ApprovalRequired: true,
		}},
	}, now); err != nil {
		t.Fatalf("put envelope fields: %v", err)
	}
	if back, err = store.Get(ctx, "tenant_delegating_001"); err != nil {
		t.Fatalf("get envelope fields: %v", err)
	}
	if !back.OperatorElevationRequiresApproval {
		t.Fatal("the organization's \"ask me before anything irreversible\" did not survive the store — the " +
			"elevation is then created not requiring approval, and this one fails OPEN")
	}
	if len(back.OperatorElevations) != 1 || back.OperatorElevations[0].ID != "elev_1" ||
		!back.OperatorElevations[0].ApprovalRequired {
		t.Fatalf("the elevation history did not survive the store: %#v — the customer's only record that the "+
			"operator ever used the envelope", back.OperatorElevations)
	}
	if back.Timezone != "Asia/Tokyo" {
		t.Fatalf("timezone = %q, want Asia/Tokyo — every organization would read UTC", back.Timezone)
	}

	// Withdrawal must travel too — a delegation that can only be turned ON is not a delegation.
	withdrawn := "2026-06-28T03:00:00Z"
	customer := "adm_customer"
	if _, err := store.Put(ctx, adminTenantModel{
		TenantID: "tenant_delegating_001", DisplayName: "Delegating", Status: "active",
		OperatorManaged:             false,
		OperatorDelegationChangedAt: &withdrawn,
		OperatorDelegationChangedBy: &customer,
	}, now); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if back, err = store.Get(ctx, "tenant_delegating_001"); err != nil || back.OperatorManaged {
		t.Fatalf("withdrawal did not survive the store: %#v (err %v)", back, err)
	}
	if back.OperatorDelegationChangedBy == nil || *back.OperatorDelegationChangedBy != customer {
		t.Fatalf("the withdrawal must name who withdrew it, got %v", back.OperatorDelegationChangedBy)
	}
	// A tenant that has never delegated carries no stamp: "never moved" and "moved at the zero time" are
	// different facts, and a column that cannot tell them apart makes an untouched delegation read as freshly
	// granted.
	untouched, err := store.Get(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("get untouched: %v", err)
	}
	if untouched.OperatorManaged || untouched.OperatorDelegationChangedAt != nil || untouched.OperatorDelegationChangedBy != nil {
		t.Fatalf("an untouched delegation must be empty, got %#v", untouched)
	}
	if err := store.Delete(ctx, "tenant_delegating_001"); err != nil {
		t.Fatalf("cleanup delegating tenant: %v", err)
	}

	// Delete is idempotent (second delete still succeeds) and removes the row.
	if err := store.Delete(ctx, "tenant_acme_001"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := store.Delete(ctx, "tenant_acme_001"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	after, err := store.List(ctx)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(after) != 1 || after[0].TenantID != "tenant_lab_001" {
		t.Fatalf("list after delete = %#v, want only lab", after)
	}

	// Get on a missing tenant yields a normalized default (matching the file store contract).
	missing, err := store.Get(ctx, "tenant_ghost_001")
	if err != nil {
		t.Fatalf("get missing: %v", err)
	}
	if missing.TenantID != "tenant_ghost_001" || missing.Status != "active" {
		t.Fatalf("missing default = %#v, want ghost/active", missing)
	}
}

func TestPostgresPurgeOrderAcknowledgementE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	// Connection-local table leaves existing tenant registry data untouched.
	if _, err = db.Exec(`CREATE TEMP TABLE admin_tenant_model_purge_orders (tenant_id text PRIMARY KEY, ordered_at timestamptz NOT NULL, CHECK (tenant_id <> 'refused'))`); err != nil {
		t.Fatal(err)
	}
	s := &postgresAdminTenantModelStore{db: db}
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.OrderPurge("refused", now); !errors.Is(err, errAdminTenantSaveUnconfirmed) {
		t.Fatalf("missing save error: %v", err)
	}
	if s.ConfigGeneration() != 0 || len(s.PurgeOrders()) != 0 {
		t.Fatal("refused order published")
	}
	for i := 0; i < 2; i++ {
		if err := s.OrderPurge("target", now.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if s.ConfigGeneration() != 1 {
		t.Fatal("no-op advanced generation")
	}
	rows := s.PurgeOrders()
	if len(rows) != 1 || rows[0].OrderedAt != now.Format(time.RFC3339) {
		t.Fatal("first order not preserved", rows)
	}
	if _, err := db.Exec(`ALTER TABLE pg_temp.admin_tenant_model_purge_orders DROP CONSTRAINT admin_tenant_model_purge_orders_tenant_id_check`); err != nil {
		t.Fatal(err)
	}
	if err := s.OrderPurge("refused", now); err != nil {
		t.Fatal(err)
	}
	if len(s.PurgeOrders()) != 2 || s.ConfigGeneration() != 2 {
		t.Fatal("retry did not record order")
	}
}
