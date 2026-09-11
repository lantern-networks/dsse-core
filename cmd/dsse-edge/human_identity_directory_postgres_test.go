package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"

	"github.com/lantern-networks/dsse-core/model"
)

func TestPostgresHumanIdentityDirectoryMigrationMatchesSchemaSQL(t *testing.T) {
	migrationSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "012_human_identities.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if got, want := normalizePostgresExportTaskSQLContract(string(migrationSQL)), normalizePostgresExportTaskSQLContract(strings.Join(postgresHumanIdentityDirectorySchemaSQL(), ";\n")+"\n"); got != want {
		t.Fatalf("migration SQL drift\n got: %s\nwant: %s", got, want)
	}
}

func TestPostgresHumanIdentityImportRunIndexMigrationMatchesSQL(t *testing.T) {
	migrationSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "013_human_identity_import_run_index.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if got, want := normalizePostgresExportTaskSQLContract(string(migrationSQL)), normalizePostgresExportTaskSQLContract(strings.Join(postgresHumanIdentityImportRunIndexSQL(), ";\n")+"\n"); got != want {
		t.Fatalf("import run index migration SQL drift\n got: %s\nwant: %s", got, want)
	}
}

func TestPostgresHumanIdentitySourceIndexMigrationMatchesSQL(t *testing.T) {
	migrationSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "014_human_identity_source_index.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if got, want := normalizePostgresExportTaskSQLContract(string(migrationSQL)), normalizePostgresExportTaskSQLContract(strings.Join(postgresHumanIdentitySourceIndexSQL(), ";\n")+"\n"); got != want {
		t.Fatalf("source index migration SQL drift\n got: %s\nwant: %s", got, want)
	}
}

func TestPostgresHumanIdentitySourceStateMigrationMatchesSQL(t *testing.T) {
	migrationSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "015_human_identity_source_states.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if got, want := normalizePostgresExportTaskSQLContract(string(migrationSQL)), normalizePostgresExportTaskSQLContract(strings.Join(postgresHumanIdentitySourceStateSQL(), ";\n")+"\n"); got != want {
		t.Fatalf("source state migration SQL drift\n got: %s\nwant: %s", got, want)
	}
}

func TestPostgresHumanIdentitySourcePolicyMigrationMatchesSQL(t *testing.T) {
	migrationSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "016_human_identity_source_policies.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if got, want := normalizePostgresExportTaskSQLContract(string(migrationSQL)), normalizePostgresExportTaskSQLContract(strings.Join(postgresHumanIdentitySourcePolicySQL(), ";\n")+"\n"); got != want {
		t.Fatalf("source policy migration SQL drift\n got: %s\nwant: %s", got, want)
	}
}

func TestBuildPostgresHumanIdentityDirectoryStatements(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	email := " user@example.jp "
	expiresAt := now.Add(time.Hour).Format(time.RFC3339)
	statement, err := buildPostgresHumanIdentityDirectoryUpsertStatement(model.HumanIdentity{
		ID:        "human_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_001",
		Email:     &email,
		Source:    "idp",
		ExpiresAt: &expiresAt,
		Status:    "active",
		Metadata:  map[string]any{"department": "security"},
	}, now)
	if err != nil {
		t.Fatalf("build upsert returned error: %v", err)
	}
	if !strings.Contains(statement.SQL, "INSERT INTO human_identities") || !strings.Contains(statement.SQL, "ON CONFLICT (tenant_id, human_identity_id) DO UPDATE") {
		t.Fatalf("unexpected upsert SQL: %s", statement.SQL)
	}
	if got, want := statement.Args[3], "user@example.jp"; got != want {
		t.Fatalf("email arg = %#v, want %#v", got, want)
	}

	list, err := buildPostgresHumanIdentityDirectoryListStatement("tenant_lab_001")
	if err != nil {
		t.Fatalf("build list returned error: %v", err)
	}
	if list.SQL != "SELECT payload FROM human_identities WHERE tenant_id = $1 ORDER BY human_identity_id ASC" || len(list.Args) != 1 {
		t.Fatalf("unexpected list statement: %#v", list)
	}
	filtered, err := buildPostgresHumanIdentityDirectoryListStatement("tenant_lab_001", humanidentity.HumanIdentityDirectoryListOptions{Source: "scim", Status: "active", Limit: 25})
	if err != nil {
		t.Fatalf("build filtered list returned error: %v", err)
	}
	if filtered.SQL != "SELECT payload FROM human_identities WHERE tenant_id = $1 AND source = $2 AND status = $3 ORDER BY human_identity_id ASC LIMIT $4" || len(filtered.Args) != 4 {
		t.Fatalf("unexpected filtered list statement: %#v", filtered)
	}
	paged, err := buildPostgresHumanIdentityDirectoryListStatement("tenant_lab_001", humanidentity.HumanIdentityDirectoryListOptions{Source: "scim", Status: "active", Subject: "sub_001", Email: "user@example.jp", ImportRunID: "import_001", AfterID: "human_001", Limit: 25})
	if err != nil {
		t.Fatalf("build paged list returned error: %v", err)
	}
	if paged.SQL != "SELECT payload FROM human_identities WHERE tenant_id = $1 AND source = $2 AND status = $3 AND subject = $4 AND email = $5 AND (metadata->>'import_run_id' = $6 OR metadata->>'deactivated_by_import_run_id' = $6) AND human_identity_id > $7 ORDER BY human_identity_id ASC LIMIT $8" || len(paged.Args) != 8 {
		t.Fatalf("unexpected paged list statement: %#v", paged)
	}
	if _, err := buildPostgresHumanIdentityDirectoryListStatement("tenant_lab_001", humanidentity.HumanIdentityDirectoryListOptions{Status: "blocked"}); err == nil {
		t.Fatal("invalid status filter accepted")
	}

	stats, err := buildPostgresHumanIdentityDirectoryStatsStatement("tenant_lab_001", now)
	if err != nil {
		t.Fatalf("build stats returned error: %v", err)
	}
	if !strings.Contains(stats.SQL, "count(*) FILTER") || !strings.Contains(stats.SQL, "expires_at > $2::timestamptz") {
		t.Fatalf("unexpected stats SQL: %s", stats.SQL)
	}

	sources, err := buildPostgresHumanIdentitySourceListStatement("tenant_lab_001", now)
	if err != nil {
		t.Fatalf("build source list returned error: %v", err)
	}
	for _, pattern := range []string{
		"WITH source_rows AS",
		"SELECT source, COALESCE(max(observed_at), '')",
		"array_agg(import_run_id ORDER BY observed_at DESC, import_run_id DESC)",
		"count(*) AS total",
		"status = 'active' AND (expires_at IS NULL OR expires_at > $2::timestamptz)",
		"status = 'active' AND expires_at IS NOT NULL AND expires_at <= $2::timestamptz",
		"GROUP BY source",
		"ORDER BY source ASC",
	} {
		if !strings.Contains(sources.SQL, pattern) {
			t.Fatalf("source list SQL missing %q: %s", pattern, sources.SQL)
		}
	}
	if len(sources.Args) != 2 || sources.Args[0] != "tenant_lab_001" {
		t.Fatalf("source list args = %#v", sources.Args)
	}
	if _, err := buildPostgresHumanIdentitySourceListStatement("", now); err == nil {
		t.Fatal("empty tenant source list accepted")
	}
	sourceState, err := buildPostgresHumanIdentitySourceStateUpsertStatement(humanidentity.HumanIdentitySourceState{
		TenantID:        "tenant_lab_001",
		Source:          "scim",
		Status:          "success",
		LastImportRunID: "human_import_run_001",
		Checkpoint:      "cursor_pg_001",
		LastSuccessAt:   now.Format(time.RFC3339),
		Requested:       2,
		Upserted:        2,
		ActiveCount:     1,
		UpdatedAt:       now.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("build source state upsert returned error: %v", err)
	}
	if !strings.Contains(sourceState.SQL, "INSERT INTO human_identity_source_states") || !strings.Contains(sourceState.SQL, "checkpoint") || !strings.Contains(sourceState.SQL, "ON CONFLICT (tenant_id, source) DO UPDATE") || len(sourceState.Args) != 14 || sourceState.Args[4] != "cursor_pg_001" {
		t.Fatalf("unexpected source state upsert statement: %#v", sourceState)
	}
	sourceStateList, err := buildPostgresHumanIdentitySourceStateListStatement("tenant_lab_001")
	if err != nil {
		t.Fatalf("build source state list returned error: %v", err)
	}
	if sourceStateList.SQL != "SELECT payload FROM human_identity_source_states WHERE tenant_id = $1 ORDER BY source ASC" || len(sourceStateList.Args) != 1 {
		t.Fatalf("unexpected source state list statement: %#v", sourceStateList)
	}
	if _, err := buildPostgresHumanIdentitySourceStateListStatement(""); err == nil {
		t.Fatal("empty tenant source state list accepted")
	}
	sourcePolicy, err := buildPostgresHumanIdentitySourcePolicyUpsertStatement(humanidentity.HumanIdentitySourcePolicy{
		TenantID:                "tenant_lab_001",
		Source:                  "scim",
		ConnectorType:           "scim",
		Enabled:                 true,
		ReconcileMissing:        true,
		ExpectedIntervalSeconds: 3600,
		StaleAfterSeconds:       7200,
		Metadata:                map[string]any{"connector_id": "scim_lab"},
		UpdatedAt:               now.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("build source policy upsert returned error: %v", err)
	}
	if !strings.Contains(sourcePolicy.SQL, "INSERT INTO human_identity_source_policies") || !strings.Contains(sourcePolicy.SQL, "ON CONFLICT (tenant_id, source) DO UPDATE") || len(sourcePolicy.Args) != 10 || sourcePolicy.Args[2] != "scim" || sourcePolicy.Args[5] != int64(3600) {
		t.Fatalf("unexpected source policy upsert statement: %#v", sourcePolicy)
	}
	sourcePolicyList, err := buildPostgresHumanIdentitySourcePolicyListStatement("tenant_lab_001")
	if err != nil {
		t.Fatalf("build source policy list returned error: %v", err)
	}
	if sourcePolicyList.SQL != "SELECT payload FROM human_identity_source_policies WHERE tenant_id = $1 ORDER BY source ASC" || len(sourcePolicyList.Args) != 1 {
		t.Fatalf("unexpected source policy list statement: %#v", sourcePolicyList)
	}
	if _, err := buildPostgresHumanIdentitySourcePolicyListStatement(""); err == nil {
		t.Fatal("empty tenant source policy list accepted")
	}

	importRuns, err := buildPostgresHumanIdentityImportRunListStatement("tenant_lab_001", humanidentity.HumanIdentityImportRunListOptions{Limit: 50})
	if err != nil {
		t.Fatalf("build import run list returned error: %v", err)
	}
	for _, pattern := range []string{
		"WITH import_events AS",
		"metadata ? 'import_run_id'",
		"metadata ? 'deactivated_by_import_run_id'",
		"array_agg(source ORDER BY observed_at DESC, source DESC)",
		"GROUP BY import_run_id",
		"ORDER BY COALESCE(max(observed_at), '') DESC, import_run_id DESC",
		"LIMIT $2",
	} {
		if !strings.Contains(importRuns.SQL, pattern) {
			t.Fatalf("import run SQL missing %q: %s", pattern, importRuns.SQL)
		}
	}
	if len(importRuns.Args) != 2 || importRuns.Args[0] != "tenant_lab_001" || importRuns.Args[1] != 50 {
		t.Fatalf("import run args = %#v", importRuns.Args)
	}
	filteredImportRuns, err := buildPostgresHumanIdentityImportRunListStatement("tenant_lab_001", humanidentity.HumanIdentityImportRunListOptions{Limit: 50, Source: "scim"})
	if err != nil {
		t.Fatalf("build source-filtered import run list returned error: %v", err)
	}
	for _, pattern := range []string{
		"metadata->>'import_source' = $2",
		"metadata->>'deactivated_by_import_source' = $2",
		"LIMIT $3",
	} {
		if !strings.Contains(filteredImportRuns.SQL, pattern) {
			t.Fatalf("source-filtered import run SQL missing %q: %s", pattern, filteredImportRuns.SQL)
		}
	}
	if len(filteredImportRuns.Args) != 3 || filteredImportRuns.Args[0] != "tenant_lab_001" || filteredImportRuns.Args[1] != "scim" || filteredImportRuns.Args[2] != 50 {
		t.Fatalf("source-filtered import run args = %#v", filteredImportRuns.Args)
	}
	if _, err := buildPostgresHumanIdentityImportRunListStatement("", humanidentity.HumanIdentityImportRunListOptions{Limit: 25}); err == nil {
		t.Fatal("empty tenant import run list accepted")
	}
	importRunDetail, err := buildPostgresHumanIdentityImportRunDetailStatement("tenant_lab_001", "import_001")
	if err != nil {
		t.Fatalf("build import run detail returned error: %v", err)
	}
	if importRunDetail.SQL != "SELECT payload FROM human_identities WHERE tenant_id = $1 AND (metadata->>'import_run_id' = $2 OR metadata->>'deactivated_by_import_run_id' = $2) ORDER BY human_identity_id ASC" || len(importRunDetail.Args) != 2 || importRunDetail.Args[0] != "tenant_lab_001" || importRunDetail.Args[1] != "import_001" {
		t.Fatalf("unexpected import run detail statement: %#v", importRunDetail)
	}
	if _, err := buildPostgresHumanIdentityImportRunDetailStatement("tenant_lab_001", "bad/run"); err == nil {
		t.Fatal("unsafe import run detail ID accepted")
	}
}

func TestSetupEdgeHumanIdentityDirectoryModes(t *testing.T) {
	store, closeFn, err := setupEdgeHumanIdentityDirectory(nil, edgeHumanIdentityDirectoryConfig{Mode: "memory"})
	if err != nil {
		t.Fatalf("memory setup returned error: %v", err)
	}
	if _, ok := store.(*humanidentity.HumanIdentityDirectoryStore); !ok {
		t.Fatalf("memory store = %T, want *humanidentity.HumanIdentityDirectoryStore", store)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("memory close returned error: %v", err)
	}
	if _, _, err := setupEdgeHumanIdentityDirectory(nil, edgeHumanIdentityDirectoryConfig{Mode: "postgres"}); err == nil || !strings.Contains(err.Error(), "identity-directory-postgres-dsn") {
		t.Fatalf("postgres without DSN error = %v", err)
	}
	if _, _, err := setupEdgeHumanIdentityDirectory(nil, edgeHumanIdentityDirectoryConfig{Mode: "bogus"}); err == nil || !strings.Contains(err.Error(), "unsupported identity directory store mode") {
		t.Fatalf("unsupported mode error = %v", err)
	}
}
