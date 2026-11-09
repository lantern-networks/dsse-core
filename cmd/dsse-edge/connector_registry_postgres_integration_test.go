package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/connector"
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

	// The remaining connector has an earlier catalog timestamp. Removing the newest row used to make
	// count(*) + max(updated_at) move backwards and strand every Edge that had seen the prior bundle.
	pgStore := store.(postgresConnectorRegistryStore)
	beforeLiveness := pgStore.ConfigGeneration()
	if changed, err := pgStore.RecordLiveness("conn_pg_001", "degraded", now.Add(4*time.Minute).Format(time.RFC3339)); err != nil || !changed {
		t.Fatalf("record connector liveness: changed=%v err=%v", changed, err)
	}
	if after := pgStore.ConfigGeneration(); after != beforeLiveness {
		t.Fatalf("liveness churned connector catalog generation: %d -> %d", beforeLiveness, after)
	}
	// What the connector reports about itself and where its tunnel is (third walk of acceptance C): kept in the
	// column and in the payload every reader uses, without moving the catalog.
	if changed, err := pgStore.RecordRuntime("tenant_lab_001", "conn_pg_001", map[string]any{"version": "0.4.1", "uptime_seconds": int64(90),
		"tunnel_region": "jp-001", "tunnel_reported_at": now.Format(time.RFC3339), "runtime_secret_hash": "sha256:00"}); err != nil || !changed {
		t.Fatalf("record connector runtime: changed=%v err=%v", changed, err)
	}
	if after := pgStore.ConfigGeneration(); after != beforeLiveness {
		t.Fatalf("runtime churned connector catalog generation: %d -> %d", beforeLiveness, after)
	}
	if got, ok := pgStore.Get("conn_pg_001"); !ok || adminConnectorVersion(got.Metadata) != "0.4.1" ||
		adminConnectorMetadataString(got.Metadata, "tunnel_region") != "jp-001" || got.Metadata["runtime_secret_hash"] == "sha256:00" {
		t.Fatalf("runtime not read back from the payload: %#v", got.Metadata)
	}
	// Review C3-R5: an observation older than what is held is refused under the row lock.
	if _, err := pgStore.RecordRuntime("tenant_lab_001", "conn_pg_001", map[string]any{"version": "0.4.1", "runtime_observed_at": now.Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	if changed, err := pgStore.RecordRuntime("tenant_lab_001", "conn_pg_001", map[string]any{"version": "0.4.0", "tunnel_region": "jp-old",
		"runtime_observed_at": now.Add(-time.Hour).Format(time.RFC3339Nano)}); err != nil || changed {
		t.Fatalf("an older observation was written: changed=%v err=%v", changed, err)
	}
	if got, _ := pgStore.Get("conn_pg_001"); adminConnectorVersion(got.Metadata) != "0.4.1" || adminConnectorMetadataString(got.Metadata, "tunnel_region") != "jp-001" {
		t.Fatalf("an older observation rolled the runtime back: %#v", got.Metadata)
	}
	// Review C3-RRR2: a registration replacing the row keeps the runtime facts the row holds at that moment,
	// inside the same transaction — not the ones its sender carried.
	current, _ := pgStore.Get("conn_pg_001")
	replay := current
	replay.Metadata = map[string]any{"version": "0.3.9", "tunnel_region": "jp-stale", "runtime_observed_at": now.Add(-2 * time.Hour).Format(time.RFC3339Nano)}
	if _, err := pgStore.Register(replay, now); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if got, _ := pgStore.Get("conn_pg_001"); adminConnectorVersion(got.Metadata) != "0.4.1" || adminConnectorMetadataString(got.Metadata, "tunnel_region") != "jp-001" {
		t.Fatalf("a registration replaced the held runtime: %#v", got.Metadata)
	}
	// Fifth review: this backend's heartbeat did not take the typed version and uptime at all.
	later := time.Now().UTC()
	if _, err := pgStore.Heartbeat(model.ConnectorHeartbeat{ID: "conn_pg_001", TenantID: "tenant_lab_001", Version: "0.4.3",
		UptimeSeconds: 5, Timestamp: later.Format(time.RFC3339Nano)}, later); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if got, _ := pgStore.Get("conn_pg_001"); adminConnectorVersion(got.Metadata) != "0.4.3" || adminConnectorUptimeSeconds(got.Metadata) == nil {
		t.Fatalf("the Postgres heartbeat did not take version and uptime: %#v", got.Metadata)
	}
	// Review C3-R6-1: a runtime write naming another organization, or none, is refused on the locked row.
	for _, tenant := range []string{"tenant_other", ""} {
		if _, err := pgStore.RecordRuntime(tenant, "conn_pg_001", map[string]any{"version": "x", "runtime_observed_at": time.Now().UTC().Format(time.RFC3339Nano)}); !errors.Is(err, connector.ErrNotThisTenantsConnector) {
			t.Fatalf("RecordRuntime for tenant %q: %v", tenant, err)
		}
		if _, err := pgStore.RecordAttachedRegion(tenant, "conn_pg_001", "elsewhere"); !errors.Is(err, connector.ErrNotThisTenantsConnector) {
			t.Fatalf("RecordAttachedRegion for tenant %q: %v", tenant, err)
		}
	}
	if got, _ := pgStore.Get("conn_pg_001"); adminConnectorVersion(got.Metadata) != "0.4.3" {
		t.Fatalf("a refused write changed the row: %#v", got.Metadata)
	}
	// Seventh review: the attachment update is one locked UPDATE. It records the region without moving the
	// catalogue generation, and it never re-creates a registration that was removed.
	beforeAttach := pgStore.ConfigGeneration()
	if moved, err := pgStore.RecordAttachedRegion("tenant_lab_001", "conn_pg_001", "jp-002"); err != nil || !moved {
		t.Fatalf("attachment: moved=%v err=%v", moved, err)
	}
	if got, _ := pgStore.Get("conn_pg_001"); got.AttachedRegionID != "jp-002" || adminConnectorVersion(got.Metadata) != "0.4.3" {
		t.Fatalf("attachment not recorded, or it disturbed the rest of the row: %+v", got)
	}
	if after := pgStore.ConfigGeneration(); after != beforeAttach {
		t.Fatalf("recording the attached region moved the catalogue generation %d -> %d", beforeAttach, after)
	}
	if _, err := store.Register(model.ConnectorRegistration{ID: "conn_pg_gone", TenantID: "tenant_lab_001", ConnectorGroupID: "cgrp_gone",
		EdgeRegionID: "jp-001", EdgeClusterID: "edge-001", PrivateBaseURL: "http://gone-connector.local"}, now); err != nil {
		t.Fatalf("register connector to remove: %v", err)
	}
	if removed, err := pgStore.RemoveForTenant("tenant_lab_001", "conn_pg_gone"); err != nil || !removed {
		t.Fatalf("remove: removed=%v err=%v", removed, err)
	}
	if moved, err := pgStore.RecordAttachedRegion("tenant_lab_001", "conn_pg_gone", "jp-late"); err != nil || moved {
		t.Fatalf("a late attachment for a removed connector: moved=%v err=%v", moved, err)
	}
	if _, found := pgStore.Get("conn_pg_gone"); found {
		t.Fatal("a late attachment re-created a removed connector")
	}
	if _, err := store.Register(model.ConnectorRegistration{
		ID: "conn_pg_purge_001", TenantID: "tenant_purge", ConnectorGroupID: "cgrp_purge",
		EdgeRegionID: "jp-001", EdgeClusterID: "edge-001", PrivateBaseURL: "http://purge-connector.local",
	}, now); err != nil {
		t.Fatalf("register connector for purge: %v", err)
	}
	beforePurge := pgStore.ConfigGeneration()
	if row := purgeTenantRows(ctx, db, "connector_registrations", "tenant_purge", nil); row.Error != "" || row.Count != 1 {
		t.Fatalf("purge connector batch: count=%d error=%q", row.Count, row.Error)
	}
	if after := pgStore.ConfigGeneration(); after <= beforePurge {
		t.Fatalf("catalog generation did not advance on tenant purge: %d -> %d", beforePurge, after)
	}
	if _, found := pgStore.Get("conn_pg_purge_001"); found {
		t.Fatal("purged connector remains")
	}
	beforeRemoval := pgStore.ConfigGeneration()
	removed, err := pgStore.RemoveForTenant("tenant_lab_001", "conn_pg_001")
	if err != nil || !removed {
		t.Fatalf("remove newest connector: removed=%v err=%v", removed, err)
	}
	if after := pgStore.ConfigGeneration(); after <= beforeRemoval {
		t.Fatalf("catalog generation did not advance on removal: %d -> %d", beforeRemoval, after)
	}
	if other, found := pgStore.Get("conn_pg_other_001"); !found || other.TenantID != "tenant_other" {
		t.Fatalf("other tenant connector changed after removal: found=%v tenant=%q", found, other.TenantID)
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

	// Regional registration must work even while this node is not the CP leader.
	blobDB, err := newCPStateBlobDB(dsn, "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { blobDB.Close() })
	oldElector, oldRoutes := cpLeaderElectorInstance, connectorRouteGov
	cpLeaderElectorInstance = &cpLeaderElector{db: db}
	connectorRouteGov = newConnectorRouteGovernanceWithPersister("", true, &postgresBlobPersister{db: blobDB, key: "connector_route_governance"})
	t.Cleanup(func() { cpLeaderElectorInstance, connectorRouteGov = oldElector, oldRoutes })
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

	cpLeaderElectorInstance = oldElector
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
