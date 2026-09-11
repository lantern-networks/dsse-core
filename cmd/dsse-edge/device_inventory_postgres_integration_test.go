package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"

	_ "github.com/lib/pq"
)

func TestSetupEdgeDeviceStorePostgresE2E(t *testing.T) {
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
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})

	store, closeFn, err := setupEdgeDeviceStore(ctx, edgeDeviceStoreConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeDeviceStore returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeFn(); err != nil {
			t.Fatalf("close device store: %v", err)
		}
	})

	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	policyBundle := model.PolicyBundle{
		ID:       "pb_lab_001",
		TenantID: "tenant_lab_001",
		Version:  "2026.05.25.001",
	}
	device, err := store.Register(model.Device{
		ID:               "dev_pg_001",
		TenantID:         "tenant_lab_001",
		UserID:           "user_lab_001",
		Hostname:         "macbook-pg",
		OS:               "macos",
		OSVersion:        "15.5",
		AgentVersion:     "0.1.0",
		DeviceTrustLevel: "managed",
		Metadata:         map[string]any{"source": "postgres-e2e"},
	}, policyBundle, now)
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if device.PolicyBundleID != policyBundle.ID || device.Status != "registered" {
		t.Fatalf("registered device = %#v, want policy bundle defaults and registered status", device)
	}

	if _, err := store.Register(model.Device{
		ID:               "dev_pg_001",
		TenantID:         "tenant_other",
		UserID:           "user_other_001",
		Hostname:         "cross-tenant",
		OS:               "macos",
		AgentVersion:     "0.1.0",
		DeviceTrustLevel: "managed",
	}, model.PolicyBundle{ID: "pb_other_001", TenantID: "tenant_other", Version: "2026.05.25.001"}, now.Add(time.Second)); err == nil {
		t.Fatal("cross-tenant Register returned nil error")
	}
	persisted, ok := store.Get("dev_pg_001")
	if !ok || persisted.TenantID != "tenant_lab_001" || persisted.Hostname != "macbook-pg" {
		t.Fatalf("persisted device after cross-tenant Register = %#v ok=%v", persisted, ok)
	}

	heartbeat, err := store.Heartbeat(model.DeviceHeartbeat{
		ID:               "dev_pg_001",
		TenantID:         "tenant_lab_001",
		AgentVersion:     "0.1.1",
		DeviceTrustLevel: "managed",
		Status:           "healthy",
		Metadata:         map[string]any{"steering": "ok"},
	}, policyBundle, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Heartbeat returned error: %v", err)
	}
	if heartbeat.AgentVersion != "0.1.1" || heartbeat.Status != "healthy" || heartbeat.Metadata["steering"] != "ok" {
		t.Fatalf("heartbeat device = %#v, want merged heartbeat fields", heartbeat)
	}

	tenantReader, ok := store.(deviceTenantReader)
	if !ok {
		t.Fatalf("postgres device store = %T, want deviceTenantReader", store)
	}
	devices, err := tenantReader.ListByTenant("tenant_lab_001")
	if err != nil {
		t.Fatalf("ListByTenant returned error: %v", err)
	}
	if len(devices) != 1 || devices[0].ID != "dev_pg_001" {
		t.Fatalf("tenant devices = %#v, want dev_pg_001 only", devices)
	}
	otherDevices, err := tenantReader.ListByTenant("tenant_other")
	if err != nil {
		t.Fatalf("ListByTenant other returned error: %v", err)
	}
	if len(otherDevices) != 0 {
		t.Fatalf("other tenant devices = %#v, want none", otherDevices)
	}
}
