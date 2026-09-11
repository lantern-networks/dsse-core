package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
)

func TestConnectorRegistrationHeartbeatAndRouting(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	domainOutbox := &recordingDomainEventOutbox{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:         testEvaluator(),
		Writer:            writer,
		Registry:          connector.NewRegistry(),
		DomainEventOutbox: domainOutbox,
		ProxyClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path != "/private-app/dummy" {
				t.Fatalf("path = %s, want /private-app/dummy", req.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"content-type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"reachable_via_connector"}`)),
			}, nil
		})},
	})
	registerBody := `{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_https"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{}
		}`
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(registerBody))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusCreated, registerRec.Body.String())
	}

	heartbeatReq := httptest.NewRequest(http.MethodPost, "/connectors/conn_lab_001/heartbeat", strings.NewReader(`{
		"tenant_id":"tenant_lab_001",
		"status":"healthy",
		"policy_bundle_id":"pb_lab_20260522_001",
		"policy_bundle_version":"2026.05.22.001"
		}`))
	heartbeatReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	heartbeatRec := httptest.NewRecorder()
	handler.ServeHTTP(heartbeatRec, heartbeatReq)
	if heartbeatRec.Code != http.StatusAccepted {
		t.Fatalf("heartbeat status = %d, want %d, body=%s", heartbeatRec.Code, http.StatusAccepted, heartbeatRec.Body.String())
	}

	proxyReq := httptest.NewRequest(http.MethodGet, "/apps/app_dummy_https?connector_id=conn_lab_001", nil)
	proxyRec := httptest.NewRecorder()
	handler.ServeHTTP(proxyRec, proxyReq)
	if proxyRec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, want %d, body=%s", proxyRec.Code, http.StatusOK, proxyRec.Body.String())
	}
	if !strings.Contains(proxyRec.Body.String(), "reachable_via_connector") {
		t.Fatalf("proxy body = %s", proxyRec.Body.String())
	}
	assertLogExists(t, logDir, "access.log.jsonl")
	assertLogExists(t, logDir, "connector.log.jsonl")
	accessLog, err := os.ReadFile(filepath.Join(logDir, "access.log.jsonl"))
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if !strings.Contains(string(accessLog), `"connector_id":"conn_lab_001"`) {
		t.Fatalf("access log = %s, want connector_id", string(accessLog))
	}
	connectorLog, err := os.ReadFile(filepath.Join(logDir, "connector.log.jsonl"))
	if err != nil {
		t.Fatalf("read connector log: %v", err)
	}
	if !strings.Contains(string(connectorLog), "access_decision_id") {
		t.Fatalf("connector log = %s, want access_decision_id", string(connectorLog))
	}

	denyReq := httptest.NewRequest(http.MethodGet, "/apps/app_dummy_https?connector_id=conn_lab_001&actor_nhi_id=nhi_missing_001", nil)
	denyRec := httptest.NewRecorder()
	handler.ServeHTTP(denyRec, denyReq)
	if denyRec.Code != http.StatusForbidden {
		t.Fatalf("deny status = %d, want %d, body=%s", denyRec.Code, http.StatusForbidden, denyRec.Body.String())
	}
	connectorLog, err = os.ReadFile(filepath.Join(logDir, "connector.log.jsonl"))
	if err != nil {
		t.Fatalf("read connector log after deny: %v", err)
	}
	if !strings.Contains(string(connectorLog), "connector_route_denied") {
		t.Fatalf("connector log = %s, want connector_route_denied", string(connectorLog))
	}
	domainEvents := domainOutbox.insertedEvents()
	counts := map[string]int{}
	for _, event := range domainEvents {
		counts[event.Stream]++
		if event.Stream == "connector_logs" && (event.EventPlane != "access" || event.EventType != "connector_log_recorded" || event.Payload["connector_id"] != "conn_lab_001") {
			t.Fatalf("connector domain event = %#v", event)
		}
	}
	if counts["connector_logs"] != 4 || counts["access_logs"] != 2 || counts["decision_traces"] != 0 {
		t.Fatalf("domain event counts = %#v from events %#v", counts, domainEvents)
	}
}

func TestConnectorRegistrationRequiresSharedSecret(t *testing.T) {
	handler := newTestHandler(t)
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_https"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{}
	}`))
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusUnauthorized {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusUnauthorized, registerRec.Body.String())
	}
}

func TestConnectorRuntimeSecretOverridesSharedSecret(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        connector.NewRegistry(),
		ConnectorSecret: "bootstrap-secret",
		LabMode:         boolPtr(false),
	})

	registerBody := fmt.Sprintf(`{
		"id":"conn_runtime_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Runtime Secret Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_https"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{"runtime_secret_hash":%q}
	}`, connectorRuntimeSecretHash("runtime-secret"))
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(registerBody))
	registerReq.Header.Set(connectorSecretHeader, "bootstrap-secret")
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusCreated, registerRec.Body.String())
	}
	registerResponseBody := registerRec.Body.String()
	if strings.Contains(registerResponseBody, "runtime_secret_hash") || strings.Contains(registerResponseBody, connectorRuntimeSecretHash("runtime-secret")) {
		t.Fatalf("register response leaked runtime hash: %s", registerResponseBody)
	}
	if !strings.Contains(registerResponseBody, `"runtime_secret_configured":true`) {
		t.Fatalf("register response = %s, want runtime_secret_configured", registerResponseBody)
	}

	heartbeatBody := `{
		"tenant_id":"tenant_lab_001",
		"status":"healthy",
		"policy_bundle_id":"pb_lab_20260522_001",
		"policy_bundle_version":"2026.05.22.001"
	}`
	heartbeatReq := httptest.NewRequest(http.MethodPost, "/connectors/conn_runtime_001/heartbeat", strings.NewReader(heartbeatBody))
	heartbeatReq.Header.Set(connectorSecretHeader, "bootstrap-secret")
	heartbeatRec := httptest.NewRecorder()
	handler.ServeHTTP(heartbeatRec, heartbeatReq)
	if heartbeatRec.Code != http.StatusUnauthorized {
		t.Fatalf("bootstrap heartbeat status = %d, want %d", heartbeatRec.Code, http.StatusUnauthorized)
	}

	heartbeatReq = httptest.NewRequest(http.MethodPost, "/connectors/conn_runtime_001/heartbeat", strings.NewReader(heartbeatBody))
	heartbeatReq.Header.Set(connectorSecretHeader, "runtime-secret")
	heartbeatRec = httptest.NewRecorder()
	handler.ServeHTTP(heartbeatRec, heartbeatReq)
	if heartbeatRec.Code != http.StatusAccepted {
		t.Fatalf("runtime heartbeat status = %d, want %d, body=%s", heartbeatRec.Code, http.StatusAccepted, heartbeatRec.Body.String())
	}

	dueReq := httptest.NewRequest(http.MethodGet, "/identity-sources/due", nil)
	dueReq.Header.Set(connectorSecretHeader, "bootstrap-secret")
	dueReq.Header.Set(connectorIDHeader, "conn_runtime_001")
	dueRec := httptest.NewRecorder()
	handler.ServeHTTP(dueRec, dueReq)
	if dueRec.Code != http.StatusUnauthorized {
		t.Fatalf("bootstrap due status = %d, want %d", dueRec.Code, http.StatusUnauthorized)
	}

	dueReq = httptest.NewRequest(http.MethodGet, "/identity-sources/due", nil)
	dueReq.Header.Set(connectorSecretHeader, "runtime-secret")
	dueReq.Header.Set(connectorIDHeader, "conn_runtime_001")
	dueRec = httptest.NewRecorder()
	handler.ServeHTTP(dueRec, dueReq)
	if dueRec.Code != http.StatusOK {
		t.Fatalf("runtime due status = %d, want %d, body=%s", dueRec.Code, http.StatusOK, dueRec.Body.String())
	}
}

func TestConnectorRegistrationRejectsInvalidRuntimeSecretHash(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        connector.NewRegistry(),
		ConnectorSecret: defaultConnectorSecret,
	})
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_https"],
		"private_base_url":"http://connector.local",
		"status":"registered",
		"metadata":{"runtime_secret_hash":"sha256:not-valid"}
	}`))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusBadRequest {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusBadRequest, registerRec.Body.String())
	}
}

func TestConnectorRegistrationDoesNotFallbackWhenRegistryLookupFails(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        postgresConnectorRegistryStore{},
		ConnectorSecret: defaultConnectorSecret,
		LabMode:         boolPtr(false),
	})
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
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
	if registerRec.Code != http.StatusInternalServerError {
		t.Fatalf("registry failure register status = %d, want %d, body=%s", registerRec.Code, http.StatusInternalServerError, registerRec.Body.String())
	}
}

func TestConnectorRegistrationRejectsOversizedBodyBeforeAuth(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        connector.NewRegistry(),
		ConnectorSecret: defaultConnectorSecret,
		LabMode:         boolPtr(false),
	})
	body := `{"id":"conn_lab_001","tenant_id":"tenant_lab_001","private_base_url":"http://connector.local","metadata":{"padding":"` + strings.Repeat("x", maxConnectorRegistrationBodyBytes) + `"}}`
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(body))
	registerReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	registerRec := httptest.NewRecorder()
	handler.ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusBadRequest {
		t.Fatalf("oversized register status = %d, want %d, body=%s", registerRec.Code, http.StatusBadRequest, registerRec.Body.String())
	}
	if !strings.Contains(registerRec.Body.String(), "request body too large") {
		t.Fatalf("oversized register body = %s, want size error", registerRec.Body.String())
	}
}

func TestConnectorRuntimeSecretRotationEndpoint(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	// Drives an admin route with the shared break-glass token, which is off by default now.
	armBreakGlassForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        connector.NewRegistry(),
		ConnectorSecret: defaultConnectorSecret,
		AdminToken:      "legacy-admin-token",
		LabMode:         boolPtr(false),
	})
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
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

	rotateReq := httptest.NewRequest(http.MethodPost, "/connectors/conn_lab_001/runtime-secret/rotate", strings.NewReader(`{"runtime_secret":"rotated-runtime-secret-0001"}`))
	rotateRec := httptest.NewRecorder()
	handler.ServeHTTP(rotateRec, rotateReq)
	if rotateRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized rotate status = %d, want %d", rotateRec.Code, http.StatusUnauthorized)
	}

	rotateReq = httptest.NewRequest(http.MethodPost, "/connectors/conn_lab_001/runtime-secret/rotate", strings.NewReader(`{"runtime_secret":"too-short"}`))
	rotateReq.Header.Set("authorization", "Bearer legacy-admin-token")
	rotateRec = httptest.NewRecorder()
	handler.ServeHTTP(rotateRec, rotateReq)
	if rotateRec.Code != http.StatusBadRequest {
		t.Fatalf("short rotate status = %d, want %d", rotateRec.Code, http.StatusBadRequest)
	}

	rotateReq = httptest.NewRequest(http.MethodPost, "/connectors/conn_lab_001/runtime-secret/rotate", strings.NewReader(`{"runtime_secret":"rotated-runtime-secret-0001"}`))
	rotateReq.Header.Set("authorization", "Bearer legacy-admin-token")
	rotateRec = httptest.NewRecorder()
	handler.ServeHTTP(rotateRec, rotateReq)
	if rotateRec.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, want %d, body=%s", rotateRec.Code, http.StatusOK, rotateRec.Body.String())
	}
	var rotateResponse connectorRuntimeSecretRotateResponse
	if err := json.NewDecoder(rotateRec.Body).Decode(&rotateResponse); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	if rotateResponse.RuntimeSecret != "rotated-runtime-secret-0001" || rotateResponse.RotatedAt == "" {
		t.Fatalf("rotate response = %#v", rotateResponse)
	}
	if rotateResponse.Connector.Metadata["runtime_secret_configured"] != true {
		t.Fatalf("rotate connector metadata = %#v, want runtime_secret_configured", rotateResponse.Connector.Metadata)
	}
	if rotateResponse.Connector.Metadata["runtime_secret_rotated_at"] == "" || rotateResponse.Connector.Metadata["runtime_secret_rotated_by"] != "admin_legacy_token" {
		t.Fatalf("rotate connector metadata = %#v, want rotation metadata", rotateResponse.Connector.Metadata)
	}
	if _, ok := rotateResponse.Connector.Metadata["runtime_secret_hash"]; ok {
		t.Fatalf("rotate response leaked runtime hash: %#v", rotateResponse.Connector.Metadata)
	}

	heartbeatBody := `{"tenant_id":"tenant_lab_001","status":"healthy","policy_bundle_id":"pb_lab_20260522_001","policy_bundle_version":"2026.05.22.001"}`
	heartbeatReq := httptest.NewRequest(http.MethodPost, "/connectors/conn_lab_001/heartbeat", strings.NewReader(heartbeatBody))
	heartbeatReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	heartbeatRec := httptest.NewRecorder()
	handler.ServeHTTP(heartbeatRec, heartbeatReq)
	if heartbeatRec.Code != http.StatusUnauthorized {
		t.Fatalf("old secret heartbeat status = %d, want %d", heartbeatRec.Code, http.StatusUnauthorized)
	}
	heartbeatReq = httptest.NewRequest(http.MethodPost, "/connectors/conn_lab_001/heartbeat", strings.NewReader(heartbeatBody))
	heartbeatReq.Header.Set(connectorSecretHeader, "rotated-runtime-secret-0001")
	heartbeatRec = httptest.NewRecorder()
	handler.ServeHTTP(heartbeatRec, heartbeatReq)
	if heartbeatRec.Code != http.StatusAccepted {
		t.Fatalf("rotated secret heartbeat status = %d, want %d, body=%s", heartbeatRec.Code, http.StatusAccepted, heartbeatRec.Body.String())
	}

	reregisterReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector Reregistered",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_https"],
		"private_base_url":"http://updated-connector.local",
		"status":"registered",
		"metadata":{"identity_sync":{"configured":true}}
	}`))
	reregisterReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	reregisterRec := httptest.NewRecorder()
	handler.ServeHTTP(reregisterRec, reregisterReq)
	if reregisterRec.Code != http.StatusUnauthorized {
		t.Fatalf("reregister with shared secret status = %d, want %d", reregisterRec.Code, http.StatusUnauthorized)
	}
	reregisterReq = httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector Reregistered",
		"edge_region_id":"local",
		"edge_cluster_id":"local-edge-001",
		"application_ids":["app_dummy_https"],
		"private_base_url":"http://updated-connector.local",
		"status":"registered",
		"metadata":{"identity_sync":{"configured":true}}
	}`))
	reregisterReq.Header.Set(connectorSecretHeader, "rotated-runtime-secret-0001")
	reregisterRec = httptest.NewRecorder()
	handler.ServeHTTP(reregisterRec, reregisterReq)
	if reregisterRec.Code != http.StatusCreated {
		t.Fatalf("reregister with runtime secret status = %d, want %d, body=%s", reregisterRec.Code, http.StatusCreated, reregisterRec.Body.String())
	}

	heartbeatReq = httptest.NewRequest(http.MethodPost, "/connectors/conn_lab_001/heartbeat", strings.NewReader(heartbeatBody))
	heartbeatReq.Header.Set(connectorSecretHeader, defaultConnectorSecret)
	heartbeatRec = httptest.NewRecorder()
	handler.ServeHTTP(heartbeatRec, heartbeatReq)
	if heartbeatRec.Code != http.StatusUnauthorized {
		t.Fatalf("old secret heartbeat after reregister status = %d, want %d", heartbeatRec.Code, http.StatusUnauthorized)
	}
	heartbeatReq = httptest.NewRequest(http.MethodPost, "/connectors/conn_lab_001/heartbeat", strings.NewReader(heartbeatBody))
	heartbeatReq.Header.Set(connectorSecretHeader, "rotated-runtime-secret-0001")
	heartbeatRec = httptest.NewRecorder()
	handler.ServeHTTP(heartbeatRec, heartbeatReq)
	if heartbeatRec.Code != http.StatusAccepted {
		t.Fatalf("rotated secret heartbeat after reregister status = %d, want %d, body=%s", heartbeatRec.Code, http.StatusAccepted, heartbeatRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/connectors", nil)
	listReq.Header.Set("authorization", "Bearer legacy-admin-token")
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("connector list after reregister status = %d, want %d, body=%s", listRec.Code, http.StatusOK, listRec.Body.String())
	}
	listBody := listRec.Body.String()
	if strings.Contains(listBody, "runtime_secret_hash") || strings.Contains(listBody, connectorRuntimeSecretHash("rotated-runtime-secret-0001")) {
		t.Fatalf("connector list leaked runtime hash after reregister: %s", listBody)
	}
	if !strings.Contains(listBody, `"runtime_secret_configured":true`) || !strings.Contains(listBody, `"runtime_secret_rotated_by":"admin_legacy_token"`) {
		t.Fatalf("connector list after reregister = %s, want preserved runtime metadata", listBody)
	}
	if !strings.Contains(listBody, `"status":"healthy"`) {
		t.Fatalf("connector list after reregister = %s, want preserved heartbeat status", listBody)
	}

	connectorRows, err := writer.ReadJSONL("connector.log.jsonl")
	if err != nil {
		t.Fatalf("read connector log: %v", err)
	}
	foundRotation := false
	for _, row := range connectorRows {
		if row["event_type"] == "connector_runtime_secret_rotated" {
			foundRotation = true
			if row["rotated_by"] != "admin_legacy_token" {
				t.Fatalf("rotation row = %#v, want rotated_by admin_legacy_token", row)
			}
		}
	}
	if !foundRotation {
		t.Fatalf("connector rows = %#v, want rotation event", connectorRows)
	}
}

func TestConnectorRuntimeSecretRotationEndpointGeneratesSecret(t *testing.T) {
	// Drives an admin route with the shared break-glass token, which is off by default now.
	armBreakGlassForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        connector.NewRegistry(),
		ConnectorSecret: defaultConnectorSecret,
		AdminToken:      "legacy-admin-token",
		LabMode:         boolPtr(false),
	})
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_lab_001",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
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

	rotateReq := httptest.NewRequest(http.MethodPost, "/connectors/conn_lab_001/runtime-secret/rotate", strings.NewReader(`{}`))
	rotateReq.Header.Set("authorization", "Bearer legacy-admin-token")
	rotateRec := httptest.NewRecorder()
	handler.ServeHTTP(rotateRec, rotateReq)
	if rotateRec.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, want %d, body=%s", rotateRec.Code, http.StatusOK, rotateRec.Body.String())
	}
	var rotateResponse connectorRuntimeSecretRotateResponse
	if err := json.NewDecoder(rotateRec.Body).Decode(&rotateResponse); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	if len(rotateResponse.RuntimeSecret) < 32 {
		t.Fatalf("generated runtime secret length = %d, want >=32", len(rotateResponse.RuntimeSecret))
	}
	if rotateResponse.Connector.Metadata["runtime_secret_configured"] != true {
		t.Fatalf("rotate connector metadata = %#v, want runtime_secret_configured", rotateResponse.Connector.Metadata)
	}
}

func TestConnectorRegistrationRejectsTenantMismatch(t *testing.T) {
	handler := newTestHandler(t)
	registerReq := httptest.NewRequest(http.MethodPost, "/connectors/register", strings.NewReader(`{
		"id":"conn_lab_001",
		"tenant_id":"tenant_other",
		"connector_group_id":"cgrp_lab_001",
		"name":"Lab Connector",
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
	if registerRec.Code != http.StatusForbidden {
		t.Fatalf("register status = %d, want %d, body=%s", registerRec.Code, http.StatusForbidden, registerRec.Body.String())
	}
}

func TestRuntimeDecisionEndpointUsesConnectorRuntimeSecretWhenConnectorIDPresent(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_runtime_001",
		TenantID:       "tenant_lab_001",
		Name:           "Runtime Secret Connector",
		PrivateBaseURL: "http://connector.local",
		Metadata: map[string]any{
			"runtime_secret_hash": connectorRuntimeSecretHash("runtime-secret"),
		},
	}, time.Now()); err != nil {
		t.Fatalf("register connector returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        registry,
		ConnectorSecret: "bootstrap-secret",
		LabMode:         boolPtr(false),
	})
	body := `{"tenant_id":"tenant_lab_001","user_id":"user_lab_001","application_id":"app_dummy_https","service_family":"https"}`

	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	req.Header.Set(connectorIDHeader, "conn_runtime_001")
	req.Header.Set(connectorSecretHeader, "bootstrap-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bootstrap decision status = %d, want %d, body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	req.Header.Set(connectorIDHeader, "conn_runtime_001")
	req.Header.Set(connectorSecretHeader, "runtime-secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("runtime decision status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestRuntimeDecisionEndpointRejectsCrossTenantConnectorRuntimeSecret(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_other_runtime_001",
		TenantID:       "tenant_other",
		Name:           "Other Runtime Secret Connector",
		PrivateBaseURL: "http://other-connector.local",
		Metadata: map[string]any{
			"runtime_secret_hash": connectorRuntimeSecretHash("other-runtime-secret"),
		},
	}, time.Now()); err != nil {
		t.Fatalf("register connector returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:       testEvaluator(),
		Writer:          writer,
		Registry:        registry,
		ConnectorSecret: "bootstrap-secret",
		LabMode:         boolPtr(false),
	})
	body := `{"tenant_id":"tenant_lab_001","user_id":"user_lab_001","application_id":"app_dummy_https","service_family":"https"}`

	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	req.Header.Set(connectorIDHeader, "conn_other_runtime_001")
	req.Header.Set(connectorSecretHeader, "other-runtime-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cross-tenant runtime decision status = %d, want %d, body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

func TestRuntimeDecisionEndpointCanRequireConnectorRuntimeSecret(t *testing.T) {
	relaxConnectorMTLSPresentationForTest(t)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_runtime_001",
		TenantID:       "tenant_lab_001",
		Name:           "Runtime Secret Connector",
		PrivateBaseURL: "http://connector.local",
		Metadata: map[string]any{
			"runtime_secret_hash": connectorRuntimeSecretHash("runtime-secret"),
		},
	}, time.Now()); err != nil {
		t.Fatalf("register connector returned error: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:                     testEvaluator(),
		Writer:                        writer,
		Registry:                      registry,
		ConnectorSecret:               "bootstrap-secret",
		RequireConnectorRuntimeSecret: true,
		LabMode:                       boolPtr(false),
	})
	body := `{"tenant_id":"tenant_lab_001","user_id":"user_lab_001","application_id":"app_dummy_https","service_family":"https"}`

	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	req.Header.Set(connectorSecretHeader, "bootstrap-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing connector id status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	req.Header.Set(connectorIDHeader, "conn_missing")
	req.Header.Set(connectorSecretHeader, "bootstrap-secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing connector runtime hash status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	req = httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(body))
	req.Header.Set(connectorIDHeader, "conn_runtime_001")
	req.Header.Set(connectorSecretHeader, "runtime-secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("runtime decision status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// ★ THE QUESTION CHANGED FROM "WHICH DATABASE" TO "WHICH DEPLOYMENT" (2026-08-19). This used to assert that a
// non-lab node with a MEMORY or FILE connector registry could fall back to the one shared -connector-secret,
// and that assertion is what the reference deployment then did: the enforcing Edge is deliberately zero-DB and
// keeps that registry in a file, so it ran outside lab-mode with every connector authenticating by one secret.
// A guard keyed on the storage backend does not cover the topology this product recommends.
func TestConnectorRuntimeSecretRequiredConfigRejectsSharedSecretOutsideLabMode(t *testing.T) {
	for name, tc := range map[string]struct {
		devMode                       bool
		connectorRegistryStoreMode    string
		requireConnectorRuntimeSecret bool
		wantErr                       bool
	}{
		"lab mode allows the shared secret": {devMode: true, connectorRegistryStoreMode: "postgres"},
		"non lab file registry still requires a per-connector secret": {
			connectorRegistryStoreMode: "/state/connector_registry.json",
			wantErr:                    true,
		},
		"non lab memory registry still requires a per-connector secret": {
			connectorRegistryStoreMode: "memory",
			wantErr:                    true,
		},
		"non lab postgres requires runtime secret": {
			connectorRegistryStoreMode: "postgres",
			wantErr:                    true,
		},
		"non lab postgres accepts runtime secret": {
			connectorRegistryStoreMode:    " POSTGRES ",
			requireConnectorRuntimeSecret: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateConnectorRuntimeSecretRequiredConfig(tc.devMode, tc.connectorRegistryStoreMode, tc.requireConnectorRuntimeSecret)
			if tc.wantErr && err == nil {
				t.Fatalf("validateConnectorRuntimeSecretRequiredConfig returned nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateConnectorRuntimeSecretRequiredConfig returned error: %v", err)
			}
		})
	}
}
