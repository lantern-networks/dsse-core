package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

func TestAdminConnectorManagementOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    AdminConnector:",
		"    AdminConnectorList:",
		"    AdminConnectorRuntimeSecretRotateRequest:",
		"    AdminConnectorRuntimeSecretRotateResponse:",
		"  /admin/connectors:",
		"  /admin/connectors/{connector_id}:",
		"  /admin/connectors/{connector_id}/runtime-secret/rotate:",
		"admin.connectors.read",
		"admin.connectors.write",
		`$ref: "#/components/schemas/AdminConnectorList"`,
		`$ref: "#/components/schemas/AdminConnectorRuntimeSecretRotateResponse"`,
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAdminConnectorManagementAPIListAndDetailUseAdminSafeDTO(t *testing.T) {
	registry := seedAdminConnectorRegistry(t)
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  registry,
		AdminAuth: newAdminAuthStore(),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/connectors", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "runtime_secret_hash") || strings.Contains(rec.Body.String(), "sha256:") || strings.Contains(rec.Body.String(), "http://connector-private.example.test") {
		t.Fatalf("connector list leaked raw secret hash or private base URL: %s", rec.Body.String())
	}
	var result adminConnectorListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode connector list: %v", err)
	}
	if result.Count != 1 || len(result.Connectors) != 1 {
		t.Fatalf("connector list = %#v, want one tenant connector", result)
	}
	conn := result.Connectors[0]
	if conn.ID != "conn_admin_001" || conn.TenantID != "tenant_lab_001" || conn.MetadataKeyCount != 1 || !conn.RuntimeSecretConfigured || !conn.PrivateBaseURLConfigured {
		t.Fatalf("admin connector = %#v, want sanitized tenant connector metadata", conn)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/connectors/conn_admin_001", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}
	var detail adminConnector
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode connector detail: %v", err)
	}
	if detail.ID != conn.ID || detail.MetadataKeyCount != 1 || len(detail.ApplicationIDs) != 2 {
		t.Fatalf("detail connector = %#v, want seeded connector detail", detail)
	}
	if detail.Version != "1.4.2" {
		t.Fatalf("detail version = %q, want connector-reported version", detail.Version)
	}
	if detail.UptimeSeconds == nil || *detail.UptimeSeconds != 3600 {
		t.Fatalf("detail uptime = %v, want 3600", detail.UptimeSeconds)
	}
	if detail.ReachableRoutes == nil {
		t.Fatalf("detail reachable routes absent, want route-layer summary")
	}
	if detail.ReachableRoutes.FQDNDomainCount != 2 || len(detail.ReachableRoutes.FQDNDomains) != 2 {
		t.Fatalf("detail fqdn routes = %#v, want two domains with count", detail.ReachableRoutes)
	}
	if detail.ReachableRoutes.CIDRCount != 1 || detail.ReachableRoutes.Namespace != "site-tokyo" {
		t.Fatalf("detail cidr/namespace routes = %#v, want one cidr and namespace", detail.ReachableRoutes)
	}
	// ★★★ UNKNOWN, NOT FALSE — and this line used to assert the opposite (2026-09-01, corrected after the
	// Console showed a site with two live connectors as "Down — 0 of 2 online").
	//
	// A node that does not hold a connector's tunnel cannot tell "nobody holds it" from "a sibling holds it",
	// and a CONTROL PLANE holds none at all. adminConnectorOnline treats a non-nil answer as authoritative and
	// never looks at the heartbeat, so asserting false here made every connector in the deployment permanently
	// offline on the only screen an operator has. The contract this test pinned was the defect.
	if detail.TunnelConnected != nil {
		t.Fatalf("detail tunnel_connected = %v, want unknown (nil) for a connector this node does not hold — "+
			"so the reader falls through to the heartbeat, which is the fleet-wide fact", *detail.TunnelConnected)
	}
}

func TestAdminConnectorTunnelStatusDerivedFromTunnelManager(t *testing.T) {
	registry := seedAdminConnectorRegistry(t)
	clientRaw, edgeRaw := net.Pipe()
	t.Cleanup(func() { _ = clientRaw.Close(); _ = edgeRaw.Close() })
	tunnelManager := tunnel.NewManagerWithRequestTimeout(500 * time.Millisecond)
	tunnelManager.Register("conn_admin_001", "tun_admin_001", tunnel.NewInProcessConn(clientRaw, true))
	handler := newServerWithConfig(serverConfig{
		Evaluator:     testEvaluator(),
		Registry:      registry,
		AdminAuth:     newAdminAuthStore(),
		TunnelManager: tunnelManager,
	})

	connectedReq := httptest.NewRequest(http.MethodGet, "/admin/connectors/conn_admin_001", nil)
	connectedRec := httptest.NewRecorder()
	handler.ServeHTTP(connectedRec, connectedReq)
	if connectedRec.Code != http.StatusOK {
		t.Fatalf("connected detail status = %d, body=%s", connectedRec.Code, connectedRec.Body.String())
	}
	var connected adminConnector
	if err := json.Unmarshal(connectedRec.Body.Bytes(), &connected); err != nil {
		t.Fatalf("decode connected detail: %v", err)
	}
	if connected.TunnelConnected == nil || !*connected.TunnelConnected {
		t.Fatalf("connector with live tunnel session tunnel_connected = %v, want true", connected.TunnelConnected)
	}

	// A registered connector with no live tunnel session must report tunnel_connected=false, not unknown.
	listReq := httptest.NewRequest(http.MethodGet, "/admin/connectors", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	var list adminConnectorListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode connector list: %v", err)
	}
	if len(list.Connectors) != 1 {
		t.Fatalf("connector list = %#v, want one tenant connector", list)
	}
	got := list.Connectors[0]
	if got.TunnelConnected == nil || !*got.TunnelConnected {
		t.Fatalf("listed connector tunnel_connected = %v, want true while session live", got.TunnelConnected)
	}

	tunnelManager.Unregister("conn_admin_001", "tun_admin_001")
	disconnectedReq := httptest.NewRequest(http.MethodGet, "/admin/connectors/conn_admin_001", nil)
	disconnectedRec := httptest.NewRecorder()
	handler.ServeHTTP(disconnectedRec, disconnectedReq)
	var disconnected adminConnector
	if err := json.Unmarshal(disconnectedRec.Body.Bytes(), &disconnected); err != nil {
		t.Fatalf("decode disconnected detail: %v", err)
	}
	// ★ AND LOSING THE SESSION MAKES IT UNKNOWN, NOT DISCONNECTED. What this test still guards is the half
	// that was always right: a live session here reads TRUE. The other half — see the note above — was the
	// defect, because this node's ignorance is not the fleet's answer.
	if disconnected.TunnelConnected != nil {
		t.Fatalf("connector without a live tunnel here = %v, want unknown (nil)", *disconnected.TunnelConnected)
	}
	if strings.Contains(disconnectedRec.Body.String(), "runtime_secret_hash") || strings.Contains(disconnectedRec.Body.String(), "sha256:") || strings.Contains(disconnectedRec.Body.String(), "connector-private.example.test") {
		t.Fatalf("connector detail leaked secret material: %s", disconnectedRec.Body.String())
	}
}

func TestAdminConnectorManagementAPIReturnsNotFoundForTenantMismatch(t *testing.T) {
	registry := seedAdminConnectorRegistry(t)
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  registry,
		AdminAuth: newAdminAuthStore(),
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/connectors/conn_other_tenant_001", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s, want tenant mismatch not found", rec.Code, rec.Body.String())
	}
}

func TestAdminConnectorManagementAPIRotatesRuntimeSecretAndAuditsNonSecretMetadata(t *testing.T) {
	registry := seedAdminConnectorRegistry(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         registry,
		AdminAuth:        seedAdminConnectorAPITokenAuth("rotation-admin", "rotation-private-token", []string{"admin.connectors.write"}),
		AdminAuditOutbox: outbox,
	})
	body := `{"runtime_secret":"rotated-runtime-secret-0001"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/connectors/conn_admin_001/runtime-secret/rotate", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", "Bearer rotation-private-token")
	req.Header.Set("X-Actor-User-ID", "forged-actor")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "runtime_secret_hash") || strings.Contains(rec.Body.String(), "sha256:") || strings.Contains(rec.Body.String(), "http://connector-private.example.test") {
		t.Fatalf("connector rotate response leaked raw secret hash or private base URL: %s", rec.Body.String())
	}
	var result adminConnectorRuntimeSecretRotateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode connector rotate response: %v", err)
	}
	if result.RuntimeSecret != "rotated-runtime-secret-0001" || result.RotatedAt == "" || !result.Connector.RuntimeSecretConfigured || result.Connector.RuntimeSecretRotatedAt == nil {
		t.Fatalf("rotate response = %#v, want one-time secret and sanitized connector metadata", result)
	}
	stored, ok := registry.Get("conn_admin_001")
	if !ok {
		t.Fatal("rotated connector not found in registry")
	}
	if got := connectorRuntimeSecretHashFromMetadata(stored.Metadata); got != connectorRuntimeSecretHash("rotated-runtime-secret-0001") {
		t.Fatalf("stored runtime secret hash = %q, want rotated hash", got)
	}
	if _, ok := stored.Metadata["runtime_secret_rotated_by"]; ok {
		t.Fatalf("stored connector metadata included raw actor user field: %#v", stored.Metadata)
	}
	domains := []model.AuditLog{}
	for _, a := range outbox.insertedAudits {
		if a.EventType == "admin_connector_runtime_secret_rotated" {
			domains = append(domains, a)
		}
	}
	if len(domains) != 1 {
		t.Fatalf("rotation domain audits=%d", len(domains))
	}
	audit := domains[0]
	if audit.SourceIP != nil || stringPtrValue(audit.ActorUserID) != "rotation-admin" || stringPtrValue(audit.Result) != "success" {
		t.Fatalf("wrong authenticated actor/result: %#v", audit)
	}
	if audit.Metadata["connector_metadata_recorded_scope"] != "none" || audit.Metadata["runtime_secret_material_recorded"] != false || audit.Metadata["runtime_secret_hash_recorded"] != false {
		t.Fatalf("connector audit metadata = %#v, want non-secret admin boundary", audit.Metadata)
	}
}

func TestAdminConnectorManagementAPIRequiresScopedAPIToken(t *testing.T) {
	readOnlyToken := seedAdminConnectorAPITokenAuth("admin_connector_reader_001", "raw-connector-reader-token", []string{"admin.connectors.read"})
	readOnlyHandler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  seedAdminConnectorRegistry(t),
		AdminAuth: readOnlyToken,
	})
	writeReq := httptest.NewRequest(http.MethodPost, "/admin/connectors/conn_admin_001/runtime-secret/rotate", strings.NewReader(`{"runtime_secret":"scope-denied-runtime-0001"}`))
	writeReq.Header.Set("authorization", "Bearer raw-connector-reader-token")
	writeRec := httptest.NewRecorder()

	readOnlyHandler.ServeHTTP(writeRec, writeReq)

	if writeRec.Code != http.StatusForbidden || !strings.Contains(writeRec.Body.String(), "admin api token scope admin.connectors.write is required") {
		t.Fatalf("write status = %d body=%s, want write scope denial", writeRec.Code, writeRec.Body.String())
	}

	writeOnlyToken := seedAdminConnectorAPITokenAuth("admin_connector_writer_001", "raw-connector-writer-token", []string{"admin.connectors.write"})
	writeOnlyHandler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  seedAdminConnectorRegistry(t),
		AdminAuth: writeOnlyToken,
	})
	readReq := httptest.NewRequest(http.MethodGet, "/admin/connectors", nil)
	readReq.Header.Set("authorization", "Bearer raw-connector-writer-token")
	readRec := httptest.NewRecorder()

	writeOnlyHandler.ServeHTTP(readRec, readReq)

	if readRec.Code != http.StatusForbidden || !strings.Contains(readRec.Body.String(), "admin api token scope admin.connectors.read is required") {
		t.Fatalf("read status = %d body=%s, want read scope denial", readRec.Code, readRec.Body.String())
	}
}

func seedAdminConnectorRegistry(t *testing.T) *connector.Registry {
	t.Helper()
	registry := connector.NewRegistry()
	now := time.Date(2026, 6, 1, 1, 2, 3, 0, time.UTC)
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:               "conn_admin_001",
		TenantID:         "tenant_lab_001",
		ConnectorGroupID: "group_admin_001",
		Name:             "Admin Connector",
		EdgeRegionID:     "jp",
		EdgeClusterID:    "edge-lab",
		ApplicationIDs:   []string{"app_private_002", "app_private_001"},
		PrivateBaseURL:   "http://connector-private.example.test",
		Status:           "healthy",
		ReachableRoutes: model.ConnectorReachableRoutes{
			FQDNDomains: []string{"*.internal.example.test", "app.internal.example.test"},
			CIDRs:       []string{"10.20.0.0/16"},
			Namespace:   "site-tokyo",
		},
		Metadata: map[string]any{
			"source":              "lab",
			"version":             "1.4.2",
			"uptime_seconds":      float64(3600),
			"runtime_secret_hash": connectorRuntimeSecretHash("original-runtime-secret-0001"),
		},
	}, now); err != nil {
		t.Fatalf("register tenant connector: %v", err)
	}
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_other_tenant_001",
		TenantID:       "tenant_other_001",
		PrivateBaseURL: "http://other-connector-private.example.test",
		Status:         "healthy",
	}, now); err != nil {
		t.Fatalf("register other tenant connector: %v", err)
	}
	return registry
}

func seedAdminConnectorAPITokenAuth(principalID, rawToken string, scopes []string) *adminAuthStore {
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        principalID,
		TenantID:  "tenant_lab_001",
		Subject:   principalID,
		Email:     principalID + "@example.test",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        principalID + "_token",
		TenantID:                  "tenant_lab_001",
		Name:                      principalID + "-token",
		TokenHash:                 adminTokenHash(rawToken),
		Roles:                     []string{"admin"},
		Scopes:                    scopes,
		CreatedByAdminPrincipalID: principalID,
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	return adminAuth
}
