package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"

	_ "github.com/lib/pq"
)

func TestPostgresConnectorRegistryStoreE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})

	store, closeFn, err := setupEdgeConnectorRegistryStore(ctx, edgeConnectorRegistryStoreConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeConnectorRegistryStore returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeFn(); err != nil {
			t.Fatalf("close connector registry store: %v", err)
		}
	})
	now := time.Date(2026, 5, 25, 1, 2, 3, 0, time.UTC)
	conn, err := store.Register(model.ConnectorRegistration{
		ID:               "conn_pg_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		Name:             "Postgres Connector",
		EdgeRegionID:     "jp-001",
		EdgeClusterID:    "edge-001",
		ApplicationIDs:   []string{"app_dummy_https"},
		PrivateBaseURL:   "http://connector.local",
		Metadata:         map[string]any{"runtime_secret_hash": connectorRuntimeSecretHash("runtime-secret")},
	}, now)
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if conn.Status != "registered" {
		t.Fatalf("registered status = %s, want registered", conn.Status)
	}
	if _, err := store.Register(model.ConnectorRegistration{
		ID:               "conn_pg_001",
		TenantID:         "tenant_other",
		ConnectorGroupID: "cgrp_other_001",
		Name:             "Cross Tenant Overwrite",
		EdgeRegionID:     "jp-001",
		EdgeClusterID:    "edge-001",
		ApplicationIDs:   []string{"app_dummy_https"},
		PrivateBaseURL:   "http://other-connector.local",
		Metadata:         map[string]any{},
	}, now.Add(time.Second)); err == nil {
		t.Fatal("cross-tenant Register returned nil error")
	}
	if got, ok := store.Get("conn_pg_001"); !ok || got.TenantID != "tenant_lab_001" || got.Name != "Postgres Connector" {
		t.Fatalf("persisted connector after cross-tenant register = %#v ok=%v", got, ok)
	}
	if _, err := store.Register(model.ConnectorRegistration{
		ID:               "conn_pg_other_001",
		TenantID:         "tenant_other",
		ConnectorGroupID: "cgrp_other_001",
		Name:             "Other Postgres Connector",
		EdgeRegionID:     "jp-001",
		EdgeClusterID:    "edge-001",
		ApplicationIDs:   []string{"app_dummy_https"},
		PrivateBaseURL:   "http://other-connector.local",
		Metadata:         map[string]any{},
	}, now); err != nil {
		t.Fatalf("Register other tenant returned error: %v", err)
	}
	reader, ok := store.(connectorRegistryTenantReader)
	if !ok {
		t.Fatalf("postgres connector registry store = %T, want connectorRegistryTenantReader", store)
	}
	tenantConnectors, err := reader.ListByTenant(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("ListByTenant returned error: %v", err)
	}
	if len(tenantConnectors) != 1 || tenantConnectors[0].ID != "conn_pg_001" {
		t.Fatalf("tenant connectors = %#v, want only conn_pg_001", tenantConnectors)
	}
	if _, ok, err := reader.GetByTenant(ctx, "tenant_lab_001", "conn_pg_other_001"); err != nil || ok {
		t.Fatalf("cross-tenant GetByTenant ok=%v err=%v, want ok=false nil err", ok, err)
	}

	heartbeat, err := store.Heartbeat(model.ConnectorHeartbeat{
		ID:                  "conn_pg_001",
		TenantID:            "tenant_lab_001",
		Status:              "healthy",
		PolicyBundleID:      "pb_lab_001",
		PolicyBundleVersion: "2026.05.25.001",
		Metadata: map[string]any{
			"runtime_secret_hash":       connectorRuntimeSecretHash("attacker-secret"),
			"runtime_secret_rotated_at": "spoofed",
			"identity_sync":             map[string]any{"configured": true},
		},
	}, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Heartbeat returned error: %v", err)
	}
	if got := connectorRuntimeSecretHashFromMetadata(heartbeat.Metadata); got != connectorRuntimeSecretHash("runtime-secret") {
		t.Fatalf("heartbeat hash = %s, want original hash", got)
	}
	if heartbeat.Metadata["runtime_secret_rotated_at"] == "spoofed" {
		t.Fatalf("heartbeat kept spoofed rotation metadata: %#v", heartbeat.Metadata)
	}

	rotatedAt := now.Add(2 * time.Minute)
	rotated, ok, err := store.RotateRuntimeSecretHashWithMetadata("conn_pg_001", connectorRuntimeSecretHash("rotated-runtime-secret-0001"), rotatedAt, "admin_001")
	if err != nil || !ok {
		t.Fatalf("RotateRuntimeSecretHashWithMetadata ok=%v err=%v", ok, err)
	}
	if got := connectorRuntimeSecretHashFromMetadata(rotated.Metadata); got != connectorRuntimeSecretHash("rotated-runtime-secret-0001") {
		t.Fatalf("rotated hash = %s, want rotated hash", got)
	}
	if rotated.Metadata["runtime_secret_rotated_by"] != "admin_001" {
		t.Fatalf("rotated metadata = %#v, want rotated_by admin_001", rotated.Metadata)
	}
	reregistered, err := store.Register(model.ConnectorRegistration{
		ID:               "conn_pg_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "cgrp_lab_001",
		Name:             "Postgres Connector Reregistered",
		EdgeRegionID:     "jp-001",
		EdgeClusterID:    "edge-001",
		ApplicationIDs:   []string{"app_dummy_https"},
		PrivateBaseURL:   "http://updated-connector.local",
		Metadata:         map[string]any{"identity_sync": map[string]any{"configured": true}},
	}, now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("same-tenant reregister returned error: %v", err)
	}
	if got := connectorRuntimeSecretHashFromMetadata(reregistered.Metadata); got != connectorRuntimeSecretHash("rotated-runtime-secret-0001") {
		t.Fatalf("reregistered hash = %s, want preserved rotated hash", got)
	}
	if reregistered.Metadata["runtime_secret_rotated_by"] != "admin_001" {
		t.Fatalf("reregistered metadata = %#v, want rotated_by admin_001", reregistered.Metadata)
	}
	if reregistered.Status != rotated.Status || reregistered.RegisteredAt != rotated.RegisteredAt || reregistered.LastHeartbeatAt != rotated.LastHeartbeatAt {
		t.Fatalf("reregistered lifecycle = status %q registered_at %q last_heartbeat_at %q, want %q %q %q", reregistered.Status, reregistered.RegisteredAt, reregistered.LastHeartbeatAt, rotated.Status, rotated.RegisteredAt, rotated.LastHeartbeatAt)
	}
	if reregistered.Name != "Postgres Connector Reregistered" || reregistered.PrivateBaseURL != "http://updated-connector.local" {
		t.Fatalf("reregistered connector = %#v, want updated non-secret fields", reregistered)
	}
	if _, ok, err := store.RotateRuntimeSecretHashForTenantWithMetadata("tenant_lab_001", "conn_pg_other_001", connectorRuntimeSecretHash("cross-tenant-rotated-secret-001"), rotatedAt, "admin_001"); err != nil || ok {
		t.Fatalf("cross-tenant RotateRuntimeSecretHashForTenantWithMetadata ok=%v err=%v, want ok=false nil err", ok, err)
	}

	got, ok := store.Get("conn_pg_001")
	if !ok {
		t.Fatal("Get returned ok=false")
	}
	if got.Metadata["runtime_secret_rotated_by"] != "admin_001" {
		t.Fatalf("persisted metadata = %#v, want rotated_by admin_001", got.Metadata)
	}
}

func TestAdminConnectorRegistryEndpointPostgresE2E(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	resetPostgresExportTaskQueueTables(t, ctx, db)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		resetPostgresExportTaskQueueTables(t, cleanupCtx, db)
		_ = db.Close()
	})

	store, closeFn, err := setupEdgeConnectorRegistryStore(ctx, edgeConnectorRegistryStoreConfig{
		Mode:          "postgres",
		DSN:           dsn,
		MigrationDir:  filepath.Join("..", "..", "migrations"),
		RunMigrations: true,
	})
	if err != nil {
		t.Fatalf("setupEdgeConnectorRegistryStore returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := closeFn(); err != nil {
			t.Fatalf("close connector registry store: %v", err)
		}
	})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "pg_admin", TenantID: "tenant_lab_001", Status: "active", IDPID: "test-fixture", Roles: []string{"admin"}})
	auth.UpsertAPIToken(adminAPIToken{ID: "pg-test-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("pg-admin-token"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "pg_admin", Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	tenantCAs, connectorTLS := postgresTestConnectorIdentity(t, "tenant_lab_001", "conn_pg_runtime_001")
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         store,
		ConnectorSecret:  defaultConnectorSecret,
		AdminAuth:        auth,
		TenantCARegistry: tenantCAs,
		LabMode:          boolPtr(false),
	})

	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_pg_runtime_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Postgres Runtime Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_https"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{}
	}`))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusCreated, registerRec.Body.String())
	}

	rotateReq := httptest.NewRequest(http.MethodPost, "/connectors/conn_pg_runtime_001/runtime-secret/rotate", strings.NewReader(`{"runtime_secret":"postgres-rotated-runtime-secret-001"}`))
	rotateReq.Header.Set("authorization", "Bearer pg-admin-token")
	rotateRec := httptest.NewRecorder()
	handler.ServeHTTP(rotateRec, rotateReq)
	if rotateRec.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, want %d, body=%s", rotateRec.Code, http.StatusOK, rotateRec.Body.String())
	}

	// Simulate an Edge process restart by constructing a new handler over the
	// same PostgreSQL-backed registry. The rotated runtime secret must survive.
	restarted := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         postgresConnectorRegistryStore{DB: db},
		ConnectorSecret:  defaultConnectorSecret,
		AdminAuth:        auth,
		TenantCARegistry: tenantCAs,
		LabMode:          boolPtr(false),
	})
	heartbeatBody := `{"tenant_id":"tenant_lab_001","status":"healthy","policy_bundle_id":"pb_lab_20260525_001","policy_bundle_version":"2026.05.25.001"}`
	oldHeartbeatReq := httptest.NewRequest(http.MethodPost, "/connectors/conn_pg_runtime_001/heartbeat", strings.NewReader(heartbeatBody))
	oldHeartbeatReq.TLS = connectorTLS
	oldHeartbeatReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	oldHeartbeatRec := httptest.NewRecorder()
	restarted.ServeHTTP(oldHeartbeatRec, oldHeartbeatReq)
	if oldHeartbeatRec.Code != http.StatusUnauthorized {
		t.Fatalf("old secret heartbeat status = %d, want %d", oldHeartbeatRec.Code, http.StatusUnauthorized)
	}
	heartbeatReq := httptest.NewRequest(http.MethodPost, "/connectors/conn_pg_runtime_001/heartbeat", strings.NewReader(heartbeatBody))
	heartbeatReq.TLS = connectorTLS
	heartbeatReq.Header.Set(connectorSecretHeader, "postgres-rotated-runtime-secret-001")
	heartbeatRec := httptest.NewRecorder()
	restarted.ServeHTTP(heartbeatRec, heartbeatReq)
	if heartbeatRec.Code != http.StatusAccepted {
		t.Fatalf("rotated secret heartbeat status = %d, want %d, body=%s", heartbeatRec.Code, http.StatusAccepted, heartbeatRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/connectors", nil)
	listReq.Header.Set("authorization", "Bearer pg-admin-token")
	listRec := httptest.NewRecorder()
	restarted.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	var connectors []model.ConnectorRegistration
	if err := json.NewDecoder(listRec.Body).Decode(&connectors); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(connectors) != 1 {
		t.Fatalf("connectors = %#v, want 1", connectors)
	}
	metadata := connectors[0].Metadata
	if metadata["runtime_secret_configured"] != true || metadata["runtime_secret_rotated_by"] != "pg_admin" {
		t.Fatalf("public connector metadata = %#v, want configured rotation metadata", metadata)
	}
	if _, ok := metadata["runtime_secret_hash"]; ok {
		t.Fatalf("public connector leaked runtime_secret_hash: %#v", metadata)
	}
}
