package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

func TestPostgresConnectorRegistryMigrationMatchesSchemaSQL(t *testing.T) {
	migrationSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "017_connector_registrations.sql"))
	if err != nil {
		t.Fatalf("read connector registry migration: %v", err)
	}
	got := normalizePostgresExportTaskSQLContract(string(migrationSQL))
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresConnectorRegistrySchemaSQL(), "\n"))
	if got != want {
		t.Fatalf("connector registry migration drift\n got: %s\nwant: %s", got, want)
	}
}

func TestSetupEdgeConnectorRegistryStoreModes(t *testing.T) {
	store, closeFn, err := setupEdgeConnectorRegistryStore(context.Background(), edgeConnectorRegistryStoreConfig{Mode: "memory"})
	if err != nil {
		t.Fatalf("setupEdgeConnectorRegistryStore memory returned error: %v", err)
	}
	if _, ok := store.(*connector.Registry); !ok {
		t.Fatalf("memory store = %T, want *connector.Registry", store)
	}
	if closeFn == nil {
		t.Fatal("memory close function is nil")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("memory close returned error: %v", err)
	}

	if _, _, err := setupEdgeConnectorRegistryStore(context.Background(), edgeConnectorRegistryStoreConfig{Mode: "postgres"}); err == nil || !strings.Contains(err.Error(), "connector-registry-postgres-dsn") {
		t.Fatalf("postgres without DSN error = %v, want DSN error", err)
	}
	if _, _, err := setupEdgeConnectorRegistryStore(context.Background(), edgeConnectorRegistryStoreConfig{Mode: "bogus"}); err == nil || !strings.Contains(err.Error(), "unsupported connector registry store mode") {
		t.Fatalf("unsupported mode error = %v", err)
	}
}

func TestBuildPostgresConnectorRegistryUpsertStatementSerializesPayload(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	conn := model.ConnectorRegistration{
		ID:               "conn_sql_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		Name:             "SQL Connector",
		EdgeRegionID:     "jp-001",
		EdgeClusterID:    "edge-001",
		ApplicationIDs:   []string{"app_dummy_https"},
		PrivateBaseURL:   "http://connector.local",
		Status:           "healthy",
		RegisteredAt:     now.Format(time.RFC3339),
		LastHeartbeatAt:  now.Format(time.RFC3339),
		Metadata: map[string]any{
			"runtime_secret_hash":       connectorRuntimeSecretHash("runtime-secret"),
			"runtime_secret_rotated_at": now.Format(time.RFC3339),
			"runtime_secret_rotated_by": "admin_001",
		},
	}
	statement, err := buildPostgresConnectorRegistryUpsertStatement(conn, now)
	if err != nil {
		t.Fatalf("buildPostgresConnectorRegistryUpsertStatement returned error: %v", err)
	}
	if !strings.Contains(statement.SQL, "INSERT INTO connector_registrations") || !strings.Contains(statement.SQL, "ON CONFLICT (connector_id) DO UPDATE") {
		t.Fatalf("statement SQL = %s", statement.SQL)
	}
	if !strings.Contains(statement.SQL, "WHERE connector_registrations.tenant_id = EXCLUDED.tenant_id") {
		t.Fatalf("statement SQL = %s, want tenant ownership guard", statement.SQL)
	}
	if got, want := len(statement.Args), 14; got != want {
		t.Fatalf("args = %#v, want %d args", statement.Args, want)
	}
	payload, ok := statement.Args[12].(string)
	if !ok || !strings.Contains(payload, `"runtime_secret_rotated_by":"admin_001"`) {
		t.Fatalf("payload arg = %#v, want serialized connector rotation metadata", statement.Args[12])
	}
}

func TestBuildPostgresConnectorRegistryGetForTenantStatementScopesTenant(t *testing.T) {
	statement, err := buildPostgresConnectorRegistryGetForTenantStatement("tenant_lab_001", "conn_sql_001", true)
	if err != nil {
		t.Fatalf("buildPostgresConnectorRegistryGetForTenantStatement returned error: %v", err)
	}
	if !strings.Contains(statement.SQL, "tenant_id = $1 AND connector_id = $2") || !strings.Contains(statement.SQL, "FOR UPDATE") {
		t.Fatalf("statement SQL = %s, want tenant-scoped FOR UPDATE", statement.SQL)
	}
	if got, want := statement.Args, []any{"tenant_lab_001", "conn_sql_001"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
	if _, err := buildPostgresConnectorRegistryGetForTenantStatement("", "conn_sql_001", true); err == nil {
		t.Fatal("empty tenant returned nil error")
	}
}

func TestBuildPostgresConnectorRegistryListByTenantStatementScopesTenant(t *testing.T) {
	statement, err := buildPostgresConnectorRegistryListByTenantStatement("tenant_lab_001")
	if err != nil {
		t.Fatalf("buildPostgresConnectorRegistryListByTenantStatement returned error: %v", err)
	}
	if !strings.Contains(statement.SQL, "WHERE tenant_id = $1") || !strings.Contains(statement.SQL, "ORDER BY connector_id ASC") {
		t.Fatalf("statement SQL = %s, want tenant-scoped ordered list", statement.SQL)
	}
	if got, want := statement.Args, []any{"tenant_lab_001"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
	if _, err := buildPostgresConnectorRegistryListByTenantStatement(""); err == nil {
		t.Fatal("empty tenant returned nil error")
	}
}

func TestNormalizeConnectorRegistrationStripsSpoofedRotationMetadata(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	conn, err := normalizeConnectorRegistration(model.ConnectorRegistration{
		ID:               "conn_norm_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		Name:             "Norm Connector",
		EdgeRegionID:     "jp-001",
		EdgeClusterID:    "edge-001",
		ApplicationIDs:   []string{"app_dummy_https"},
		PrivateBaseURL:   "http://connector.local",
		Metadata: map[string]any{
			"runtime_secret_hash":       connectorRuntimeSecretHash("runtime-secret"),
			"runtime_secret_rotated_at": "spoofed",
			"runtime_secret_rotated_by": "connector",
		},
	}, now)
	if err != nil {
		t.Fatalf("normalizeConnectorRegistration returned error: %v", err)
	}
	if conn.Status != "registered" || conn.RegisteredAt == "" || conn.LastHeartbeatAt == "" {
		t.Fatalf("normalized connector = %#v, want defaults", conn)
	}
	if _, ok := conn.Metadata["runtime_secret_rotated_at"]; ok {
		t.Fatalf("normalized metadata kept runtime_secret_rotated_at: %#v", conn.Metadata)
	}
	if _, ok := conn.Metadata["runtime_secret_rotated_by"]; ok {
		t.Fatalf("normalized metadata kept runtime_secret_rotated_by: %#v", conn.Metadata)
	}
}

func TestConnectorRuntimeSecretHashFromMetadataRequiresFullHash(t *testing.T) {
	tests := []map[string]any{
		{"runtime_secret_hash": "sha256:not-valid"},
		{"runtime_secret_hash": "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"runtime_secret_hash": 123},
	}
	for _, metadata := range tests {
		if got := connectorRuntimeSecretHashFromMetadata(metadata); got != "" {
			t.Fatalf("connectorRuntimeSecretHashFromMetadata(%#v) = %q, want empty", metadata, got)
		}
	}
	if got := connectorRuntimeSecretHashFromMetadata(map[string]any{"runtime_secret_hash": connectorRuntimeSecretHash("runtime-secret")}); got == "" {
		t.Fatal("connectorRuntimeSecretHashFromMetadata returned empty for valid hash")
	}
}
