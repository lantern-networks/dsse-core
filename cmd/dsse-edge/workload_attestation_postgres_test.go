package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPostgresWorkloadAttestationNonceMigrationMatchesSchemaSQL(t *testing.T) {
	migrationSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "011_workload_attestation_nonces.sql"))
	if err != nil {
		t.Fatalf("read workload attestation nonce migration: %v", err)
	}
	got := normalizePostgresExportTaskSQLContract(string(migrationSQL))
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresWorkloadAttestationNonceSchemaSQL(), "\n"))
	if got != want {
		t.Fatalf("workload attestation nonce migration drift\n got: %s\nwant: %s", got, want)
	}
}

func TestBuildPostgresWorkloadAttestationNonceStatements(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	expiresAt := now.Add(5 * time.Minute)
	statement, err := buildPostgresWorkloadAttestationNonceInsertStatement(" tenant_lab_001 ", " nonce_001 ", now, expiresAt)
	if err != nil {
		t.Fatalf("build insert returned error: %v", err)
	}
	if !strings.Contains(statement.SQL, "INSERT INTO workload_attestation_nonces") || !strings.Contains(statement.SQL, "ON CONFLICT (tenant_id, nonce_hash) DO UPDATE") || !strings.Contains(statement.SQL, "workload_attestation_nonces.expires_at <= EXCLUDED.created_at") {
		t.Fatalf("insert SQL = %s", statement.SQL)
	}
	if got, want := statement.Args[0], "tenant_lab_001"; got != want {
		t.Fatalf("tenant arg = %#v, want %#v", got, want)
	}
	if got, want := statement.Args[1], runtimeWorkloadAttestationNonceHash("tenant_lab_001", "nonce_001"); got != want {
		t.Fatalf("nonce hash arg = %#v, want %#v", got, want)
	}
	cleanup := buildPostgresWorkloadAttestationNonceCleanupStatement(now)
	if cleanup.SQL != "DELETE FROM workload_attestation_nonces WHERE expires_at <= $1" || len(cleanup.Args) != 1 {
		t.Fatalf("cleanup statement = %#v", cleanup)
	}
	if _, err := buildPostgresWorkloadAttestationNonceInsertStatement("", "nonce", now, expiresAt); err == nil {
		t.Fatal("insert accepted blank tenant")
	}
	if _, err := buildPostgresWorkloadAttestationNonceInsertStatement("tenant_lab_001", "", now, expiresAt); err == nil {
		t.Fatal("insert accepted blank nonce")
	}
}

func TestSetupEdgeWorkloadAttestationNonceStoreModes(t *testing.T) {
	store, closeFn, err := setupEdgeWorkloadAttestationNonceStore(nil, edgeWorkloadAttestationNonceStoreConfig{Mode: "memory"})
	if err != nil {
		t.Fatalf("setup memory returned error: %v", err)
	}
	if store == nil {
		t.Fatal("setup memory returned nil store")
	}
	if closeFn == nil {
		t.Fatal("memory closeFn is nil")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("memory closeFn returned error: %v", err)
	}
	if _, _, err := setupEdgeWorkloadAttestationNonceStore(nil, edgeWorkloadAttestationNonceStoreConfig{Mode: "postgres"}); err == nil || !strings.Contains(err.Error(), "workload-attestation-nonce-postgres-dsn") {
		t.Fatalf("postgres without DSN error = %v, want DSN error", err)
	}
	if _, _, err := setupEdgeWorkloadAttestationNonceStore(nil, edgeWorkloadAttestationNonceStoreConfig{Mode: "bogus"}); err == nil || !strings.Contains(err.Error(), "unsupported workload attestation nonce store mode") {
		t.Fatalf("bogus mode error = %v", err)
	}
}
