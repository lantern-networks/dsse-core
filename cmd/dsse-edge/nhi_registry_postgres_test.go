package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nhi "github.com/lantern-networks/dsse-core/nhi"

	"github.com/lantern-networks/dsse-core/model"
)

func TestPostgresNonHumanIdentityMigrationMatchesSchemaSQL(t *testing.T) {
	migrationSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "009_non_human_identities.sql"))
	if err != nil {
		t.Fatalf("read NHI registry migration: %v", err)
	}
	got := normalizePostgresExportTaskSQLContract(string(migrationSQL))
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresNonHumanIdentitySchemaSQL(), "\n"))
	if got != want {
		t.Fatalf("NHI registry migration drift\n got: %s\nwant: %s", got, want)
	}
}

func TestPostgresNonHumanIdentityMigrationVersions(t *testing.T) {
	if got, want := postgresNonHumanIdentityMigrationVersions(), []string{"009"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("NHI registry versions = %#v, want %#v", got, want)
	}
}

func TestSetupEdgeNonHumanIdentityStoreModes(t *testing.T) {
	store, closeFn, err := setupEdgeNonHumanIdentityStore(context.Background(), edgeNonHumanIdentityStoreConfig{Mode: "memory"})
	if err != nil {
		t.Fatalf("setupEdgeNonHumanIdentityStore memory returned error: %v", err)
	}
	if _, ok := store.(*nhi.Store); !ok {
		t.Fatalf("memory store = %T, want *nhi.Store", store)
	}
	if closeFn == nil {
		t.Fatal("memory close function is nil")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("memory close returned error: %v", err)
	}

	if _, _, err := setupEdgeNonHumanIdentityStore(context.Background(), edgeNonHumanIdentityStoreConfig{Mode: "postgres"}); err == nil || !strings.Contains(err.Error(), "nhi-registry-postgres-dsn") {
		t.Fatalf("postgres without DSN error = %v, want DSN error", err)
	}
	if _, _, err := setupEdgeNonHumanIdentityStore(context.Background(), edgeNonHumanIdentityStoreConfig{Mode: "bogus"}); err == nil || !strings.Contains(err.Error(), "unsupported NHI registry store mode") {
		t.Fatalf("unsupported mode error = %v", err)
	}
}

func TestBuildPostgresNonHumanIdentityUpsertStatementSerializesPayload(t *testing.T) {
	now := time.Date(2026, 5, 24, 1, 2, 3, 0, time.UTC)
	expiresAt := now.Add(time.Hour).Format(time.RFC3339)
	identity := model.NonHumanIdentity{
		ID:                    "nhi_sql_001",
		TenantID:              "tenant_lab_001",
		Name:                  "SQL Agent",
		NHIType:               "ai_agent",
		OwnerUserID:           "user_owner_001",
		Status:                "active",
		AllowedApplicationIDs: []string{"app_dummy_https"},
		AllowedScopes:         []string{"ticket:create"},
		AllowlistEnforced:     true,
		ExpiresAt:             &expiresAt,
		Metadata:              map[string]any{"purpose": "test"},
	}
	statement, err := buildPostgresNonHumanIdentityUpsertStatement(identity, now)
	if err != nil {
		t.Fatalf("buildPostgresNonHumanIdentityUpsertStatement returned error: %v", err)
	}
	if !strings.Contains(statement.SQL, "INSERT INTO non_human_identities") || !strings.Contains(statement.SQL, "ON CONFLICT (tenant_id, nhi_id) DO UPDATE") {
		t.Fatalf("statement SQL = %s", statement.SQL)
	}
	if got, want := len(statement.Args), 17; got != want {
		t.Fatalf("args = %#v, want %d args", statement.Args, want)
	}
	if statement.Args[0] != "tenant_lab_001" || statement.Args[1] != "nhi_sql_001" {
		t.Fatalf("tenant/id args = %#v", statement.Args[:2])
	}
	if !strings.Contains(statement.Args[15].(string), "\"id\":\"nhi_sql_001\"") || !strings.Contains(statement.Args[15].(string), "\"nhi_type\":\"ai_agent\"") {
		t.Fatalf("payload arg = %s", statement.Args[15])
	}
	if !strings.Contains(statement.Args[15].(string), "\"allowlist_enforced\":true") {
		t.Fatalf("payload arg = %s, want allowlist_enforced true", statement.Args[15])
	}
}

func TestBuildPostgresNonHumanIdentityStatementsScopeTenant(t *testing.T) {
	list, err := buildPostgresNonHumanIdentityListStatement("tenant_lab_001")
	if err != nil {
		t.Fatalf("build list statement returned error: %v", err)
	}
	if !strings.Contains(list.SQL, "WHERE tenant_id = $1") || list.Args[0] != "tenant_lab_001" {
		t.Fatalf("list statement = %#v", list)
	}
	count, err := buildPostgresNonHumanIdentityCountActiveStatement("tenant_lab_001", time.Date(2026, 5, 24, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("build count statement returned error: %v", err)
	}
	if !strings.Contains(count.SQL, "tenant_id = $1") || !strings.Contains(count.SQL, "expires_at > $2::timestamptz") {
		t.Fatalf("count statement SQL = %s", count.SQL)
	}
	usedAt := time.Date(2026, 5, 24, 2, 3, 4, 0, time.UTC)
	markUsed, err := buildPostgresNonHumanIdentityMarkUsedStatement("tenant_lab_001", "nhi_sql_001", usedAt)
	if err != nil {
		t.Fatalf("build mark used statement returned error: %v", err)
	}
	if !strings.Contains(markUsed.SQL, "WHERE tenant_id = $1 AND nhi_id = $2") || !strings.Contains(markUsed.SQL, "jsonb_set(payload, '{last_used_at}'") {
		t.Fatalf("mark used statement SQL = %s", markUsed.SQL)
	}
	if got, want := len(markUsed.Args), 4; got != want {
		t.Fatalf("mark used args = %#v, want %d args", markUsed.Args, want)
	}
	if markUsed.Args[0] != "tenant_lab_001" || markUsed.Args[1] != "nhi_sql_001" || markUsed.Args[3] != usedAt.Format(time.RFC3339) {
		t.Fatalf("mark used args = %#v", markUsed.Args)
	}
}
