package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPostgresAdminSiteMigrationMatchesSchemaSQL keeps the on-disk migration in lockstep with the in-code schema
// contract, the same fidelity guard the tenant model store uses.
func TestPostgresAdminSiteMigrationMatchesSchemaSQL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "025_admin_sites.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresAdminSiteSchemaSQL(), "\n"))
	got := normalizePostgresExportTaskSQLContract(string(data))
	if got != want {
		t.Fatalf("site migration SQL does not match schema helper\nmigration: %s\nhelper:    %s", got, want)
	}
}

// TestPostgresAdminSiteSchemaSecurityContracts pins the tenant-scoping invariant (composite PK on tenant_id).
func TestPostgresAdminSiteSchemaSecurityContracts(t *testing.T) {
	sqlText := strings.Join(postgresAdminSiteSchemaSQL(), "\n")
	for _, want := range []string{
		"PRIMARY KEY (tenant_id, site_id)",
		"tenant_id text NOT NULL",
		"site_id text NOT NULL",
		"created_at timestamptz NOT NULL",
		"updated_at timestamptz NOT NULL",
	} {
		if !strings.Contains(sqlText, want) {
			t.Fatalf("site schema SQL missing %q:\n%s", want, sqlText)
		}
	}
}

// TestPostgresAdminSiteMigrationVersions confirms the component migration set is the single 025 migration.
func TestPostgresAdminSiteMigrationVersions(t *testing.T) {
	versions := postgresAdminSiteMigrationVersions()
	if len(versions) != 1 || versions[0] != postgresMigrationAdminSites {
		t.Fatalf("site migration versions = %#v, want [%s]", versions, postgresMigrationAdminSites)
	}
}

// TestSetupPostgresAdminSiteStoreRequiresPostgresAdminAuth confirms the backend refuses to start when the admin
// auth store is not Postgres — there is no connection to reuse (fail fast, never silently degrade).
func TestSetupPostgresAdminSiteStoreRequiresPostgresAdminAuth(t *testing.T) {
	if _, err := setupPostgresAdminSiteStore(context.Background(), newAdminAuthStore(), "migrations", false); err == nil {
		t.Fatal("expected setup to fail without a Postgres admin auth store")
	}
}
