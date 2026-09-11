package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/model"
)

func TestPostgresDeviceInventoryMigrationMatchesSchemaSQL(t *testing.T) {
	migrationSQL, err := os.ReadFile(filepath.Join("..", "..", "migrations", "018_device_inventory.sql"))
	if err != nil {
		t.Fatalf("read device inventory migration: %v", err)
	}
	got := normalizePostgresExportTaskSQLContract(string(migrationSQL))
	want := normalizePostgresExportTaskSQLContract(strings.Join(postgresDeviceInventorySchemaSQL(), "\n"))
	if got != want {
		t.Fatalf("device inventory migration drift\n got: %s\nwant: %s", got, want)
	}
}

func TestSetupEdgeDeviceStoreModes(t *testing.T) {
	store, closeFn, err := setupEdgeDeviceStore(context.Background(), edgeDeviceStoreConfig{Mode: "memory"})
	if err != nil {
		t.Fatalf("setupEdgeDeviceStore memory returned error: %v", err)
	}
	if _, ok := store.(*devicestore.Store); !ok {
		t.Fatalf("memory store = %T, want *devicestore.Store", store)
	}
	if closeFn == nil {
		t.Fatal("memory close function is nil")
	}
	if err := closeFn(); err != nil {
		t.Fatalf("memory close returned error: %v", err)
	}

	if _, _, err := setupEdgeDeviceStore(context.Background(), edgeDeviceStoreConfig{Mode: "postgres"}); err == nil || !strings.Contains(err.Error(), "device-postgres-dsn") {
		t.Fatalf("postgres without DSN error = %v, want DSN error", err)
	}
	if _, _, err := setupEdgeDeviceStore(context.Background(), edgeDeviceStoreConfig{Mode: "bogus"}); err == nil || !strings.Contains(err.Error(), "unsupported device store mode") {
		t.Fatalf("unsupported mode error = %v", err)
	}
}

func TestBuildPostgresDeviceInventoryUpsertStatementSerializesPayload(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	statement, err := buildPostgresDeviceInventoryUpsertStatement(model.Device{
		ID:                  "dev_sql_001",
		TenantID:            "tenant_lab_001",
		UserID:              "user_lab_001",
		Hostname:            "macbook-sql",
		OS:                  "macos",
		OSVersion:           "15.5",
		AgentVersion:        "0.1.0",
		DeviceTrustLevel:    "managed",
		PolicyBundleID:      "pb_lab_001",
		PolicyBundleVersion: "2026.05.25.001",
		Status:              "healthy",
		RegisteredAt:        now.Format(time.RFC3339),
		LastSeenAt:          now.Format(time.RFC3339),
		Metadata:            map[string]any{"client": "localclient"},
	}, now)
	if err != nil {
		t.Fatalf("buildPostgresDeviceInventoryUpsertStatement returned error: %v", err)
	}
	if !strings.Contains(statement.SQL, "INSERT INTO device_inventory") || !strings.Contains(statement.SQL, "ON CONFLICT (device_id) DO UPDATE") {
		t.Fatalf("statement SQL = %s", statement.SQL)
	}
	if !strings.Contains(statement.SQL, "WHERE device_inventory.tenant_id = EXCLUDED.tenant_id") {
		t.Fatalf("statement SQL = %s, want tenant ownership guard", statement.SQL)
	}
	if got, want := len(statement.Args), 16; got != want {
		t.Fatalf("args = %#v, want %d", statement.Args, want)
	}
	payload, ok := statement.Args[14].(string)
	if !ok || !strings.Contains(payload, `"id":"dev_sql_001"`) || !strings.Contains(payload, `"client":"localclient"`) {
		t.Fatalf("payload arg = %#v", statement.Args[14])
	}
}

func TestBuildPostgresDeviceInventoryGetAndListScopeTenant(t *testing.T) {
	getStatement, err := buildPostgresDeviceInventoryGetForTenantStatement("tenant_lab_001", "dev_sql_001")
	if err != nil {
		t.Fatalf("buildPostgresDeviceInventoryGetForTenantStatement returned error: %v", err)
	}
	if !strings.Contains(getStatement.SQL, "tenant_id = $1 AND device_id = $2") {
		t.Fatalf("get SQL = %s, want tenant-scoped lookup", getStatement.SQL)
	}
	if got, want := getStatement.Args, []any{"tenant_lab_001", "dev_sql_001"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("get args = %#v, want %#v", got, want)
	}

	listStatement, err := buildPostgresDeviceInventoryListByTenantStatement("tenant_lab_001")
	if err != nil {
		t.Fatalf("buildPostgresDeviceInventoryListByTenantStatement returned error: %v", err)
	}
	if !strings.Contains(listStatement.SQL, "WHERE tenant_id = $1") || !strings.Contains(listStatement.SQL, "ORDER BY device_id ASC") {
		t.Fatalf("list SQL = %s, want tenant-scoped ordered list", listStatement.SQL)
	}
	if got, want := listStatement.Args, []any{"tenant_lab_001"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("list args = %#v, want %#v", got, want)
	}
}

func TestBuildPostgresDeviceInventoryStatementsValidateInputs(t *testing.T) {
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	device := model.Device{
		ID:                  "dev_sql_001",
		TenantID:            "tenant_lab_001",
		UserID:              "user_lab_001",
		Hostname:            "macbook-sql",
		OS:                  "macos",
		AgentVersion:        "0.1.0",
		PolicyBundleID:      "pb_lab_001",
		PolicyBundleVersion: "2026.05.25.001",
		RegisteredAt:        now.Format(time.RFC3339),
	}
	device.TenantID = ""
	if _, err := buildPostgresDeviceInventoryUpsertStatement(device, now); err == nil {
		t.Fatal("upsert accepted blank tenant")
	}
	if _, err := buildPostgresDeviceInventoryGetForTenantStatement("", "dev_sql_001"); err == nil {
		t.Fatal("get accepted blank tenant")
	}
	if _, err := buildPostgresDeviceInventoryListByTenantStatement(""); err == nil {
		t.Fatal("list accepted blank tenant")
	}
}
