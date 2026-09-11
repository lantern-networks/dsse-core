package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const runtimeCopyRoundTripTestTenantID = "tenant_runtime_m1188"

func TestRuntimeCopyRoundTripRejectsNonPostMethod(t *testing.T) {
	dialer := &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("unused")}
	response := serveRuntimeCopyRoundTrip(t, http.MethodGet, validRuntimeCopyRoundTripBody(t), dialer, 100*time.Millisecond)

	assertRuntimeCopyStatus(t, response, http.StatusMethodNotAllowed, "method_not_allowed")
	assertNoRuntimeCopyRouteOpened(t, dialer)
}

func TestRuntimeCopyRoundTripRejectsSchemaVersionMismatch(t *testing.T) {
	dialer := &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("unused")}
	body := validRuntimeCopyRoundTripRequest()
	body["schema_version"] = "network_extension_runtime_copy_round_trip_request.v0"
	response := serveRuntimeCopyRoundTrip(t, http.MethodPost, mustMarshalRuntimeCopyRoundTripBody(t, body), dialer, 100*time.Millisecond)

	assertRuntimeCopyStatus(t, response, http.StatusBadRequest, "invalid_schema_version")
	assertNoRuntimeCopyRouteOpened(t, dialer)
}

func TestRuntimeCopyRoundTripRejectsMissingTenantID(t *testing.T) {
	for _, tenantID := range []string{"", "   "} {
		t.Run("tenant_id="+tenantID, func(t *testing.T) {
			dialer := &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("unused")}
			body := validRuntimeCopyRoundTripRequest()
			body["tenant_id"] = tenantID
			response := serveRuntimeCopyRoundTrip(t, http.MethodPost, mustMarshalRuntimeCopyRoundTripBody(t, body), dialer, 100*time.Millisecond)

			assertRuntimeCopyStatus(t, response, http.StatusBadRequest, "invalid_tenant_id")
			assertNoRuntimeCopyRouteOpened(t, dialer)
		})
	}
}

func TestRuntimeCopyRoundTripRejectsTenantScopeMismatch(t *testing.T) {
	dialer := &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("unused")}
	body := validRuntimeCopyRoundTripRequest()
	body["tenant_id"] = runtimeCopyRoundTripTestTenantID + "_other"
	response := serveRuntimeCopyRoundTrip(t, http.MethodPost, mustMarshalRuntimeCopyRoundTripBody(t, body), dialer, 100*time.Millisecond)

	assertRuntimeCopyStatus(t, response, http.StatusBadGateway, "tenant_scope_mismatch")
	assertNoRuntimeCopyRouteOpened(t, dialer)
}

func TestRuntimeCopyRoundTripRejectsEmptyRequestID(t *testing.T) {
	dialer := &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("unused")}
	body := validRuntimeCopyRoundTripRequest()
	body["request_id"] = " "
	response := serveRuntimeCopyRoundTrip(t, http.MethodPost, mustMarshalRuntimeCopyRoundTripBody(t, body), dialer, 100*time.Millisecond)

	assertRuntimeCopyStatus(t, response, http.StatusBadRequest, "invalid_request_id")
	assertNoRuntimeCopyRouteOpened(t, dialer)
}

func TestRuntimeCopyRoundTripRejectsInvalidBase64Payload(t *testing.T) {
	dialer := &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("unused")}
	body := validRuntimeCopyRoundTripRequest()
	body["upstream_payload_b64"] = "not base64"
	response := serveRuntimeCopyRoundTrip(t, http.MethodPost, mustMarshalRuntimeCopyRoundTripBody(t, body), dialer, 100*time.Millisecond)

	assertRuntimeCopyStatus(t, response, http.StatusBadRequest, "invalid_base64_payload")
	assertNoRuntimeCopyRouteOpened(t, dialer)
}

func TestRuntimeCopyRoundTripRejectsZeroPayload(t *testing.T) {
	dialer := &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("unused")}
	body := validRuntimeCopyRoundTripRequest()
	body["upstream_payload_b64"] = base64.StdEncoding.EncodeToString(nil)
	response := serveRuntimeCopyRoundTrip(t, http.MethodPost, mustMarshalRuntimeCopyRoundTripBody(t, body), dialer, 100*time.Millisecond)

	assertRuntimeCopyStatus(t, response, http.StatusBadRequest, "empty_upstream_payload")
	assertNoRuntimeCopyRouteOpened(t, dialer)
}

func TestRuntimeCopyRoundTripRejectsOverOneMiBRequestBody(t *testing.T) {
	dialer := &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("unused")}
	response := serveRuntimeCopyRoundTrip(t, http.MethodPost, bytes.Repeat([]byte("x"), runtimeCopyRoundTripMaxRequestBodyBytes+1), dialer, 100*time.Millisecond)

	assertRuntimeCopyStatus(t, response, http.StatusRequestEntityTooLarge, "request_body_too_large")
	assertNoRuntimeCopyRouteOpened(t, dialer)
}

func TestRuntimeCopyRoundTripDefaultDeniesUnknownApplicationID(t *testing.T) {
	dialer := &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("unused")}
	body := validRuntimeCopyRoundTripRequest()
	body["application_id"] = "app_unregistered_runtime_copy"
	response := serveRuntimeCopyRoundTrip(t, http.MethodPost, mustMarshalRuntimeCopyRoundTripBody(t, body), dialer, 100*time.Millisecond)

	assertRuntimeCopyStatus(t, response, http.StatusBadGateway, "unknown_application_default_deny")
	assertNoRuntimeCopyRouteOpened(t, dialer)
}

func TestRuntimeCopyRoundTripReturnsTimeoutCategory(t *testing.T) {
	conn := newRuntimeCopyRoundTripBlockingConnection()
	dialer := &runtimeCopyRoundTripBlockingDialer{conn: conn}
	response := serveRuntimeCopyRoundTrip(t, http.MethodPost, validRuntimeCopyRoundTripBody(t), dialer, 5*time.Millisecond)

	assertRuntimeCopyStatus(t, response, http.StatusGatewayTimeout, "round_trip_timeout")
	if got := len(dialer.routes); got != 1 {
		t.Fatalf("opened routes = %d, want 1 timeout attempt", got)
	}
	if !conn.closed {
		t.Fatal("blocking connection was not closed on timeout")
	}
}

func TestRuntimeCopyRoundTripSuccessReturnsResponseSchema(t *testing.T) {
	conn := newRecordingTCPConnection("phase2-private-app-response")
	dialer := &recordingTCPConnectionDialer{conn: conn}
	response := serveRuntimeCopyRoundTrip(t, http.MethodPost, validRuntimeCopyRoundTripBody(t), dialer, 100*time.Millisecond)

	payload := assertRuntimeCopyStatus(t, response, http.StatusOK, "round_trip_completed")
	if payload["schema_version"] != runtimeCopyRoundTripResponseSchema {
		t.Fatalf("schema_version = %v, want %s", payload["schema_version"], runtimeCopyRoundTripResponseSchema)
	}
	if payload["request_id"] != "req_runtime_copy_m1188" {
		t.Fatalf("request_id = %v, want request echo", payload["request_id"])
	}
	downstream, err := base64.StdEncoding.DecodeString(payload["downstream_payload_b64"].(string))
	if err != nil {
		t.Fatalf("downstream_payload_b64 is invalid base64: %v", err)
	}
	if string(downstream) != "phase2-private-app-response" {
		t.Fatalf("downstream = %q, want private app response", downstream)
	}
	if conn.written.String() != "phase2-client-runtime-copy" {
		t.Fatalf("upstream written = %q, want payload copied to private app", conn.written.String())
	}
	if got := len(dialer.routes); got != 1 {
		t.Fatalf("opened routes = %d, want 1", got)
	}
}

func TestRuntimeCopyRoundTripMajorProtocolRoutesUseLifecycleContractMetadataOnly(t *testing.T) {
	routes, err := loadConnectorTCPRoutesFromProtectedAppMap(filepath.Join("testdata", "protected_app_map.json"))
	if err != nil {
		t.Fatalf("loadConnectorTCPRoutesFromProtectedAppMap returned error: %v", err)
	}
	tests := []struct {
		applicationID string
		host          string
		port          int
		upstream      string
		downstream    string
	}{
		{applicationID: "app_dummy_ssh", host: "dummy-ssh.local", port: 22, upstream: "ssh-upstream", downstream: "ssh-downstream"},
		{applicationID: "app_dummy_rdp", host: "dummy-rdp.local", port: 3389, upstream: "rdp-upstream", downstream: "rdp-downstream"},
		{applicationID: "app_dummy_postgres", host: "dummy-postgres.local", port: 5432, upstream: "postgres-upstream", downstream: "postgres-downstream"},
	}
	for _, test := range tests {
		t.Run(test.applicationID, func(t *testing.T) {
			body := validRuntimeCopyRoundTripRequest()
			body["request_id"] = "req_runtime_copy_" + test.applicationID + "_m1455"
			body["application_id"] = test.applicationID
			body["upstream_payload_b64"] = base64.StdEncoding.EncodeToString([]byte(test.upstream))
			conn := newRecordingTCPConnection(test.downstream)
			dialer := &recordingTCPConnectionDialer{conn: conn}
			response := serveRuntimeCopyRoundTripWithRoutes(t, http.MethodPost, mustMarshalRuntimeCopyRoundTripBody(t, body), routes, dialer, 100*time.Millisecond)

			payload := assertRuntimeCopyStatus(t, response, http.StatusOK, "round_trip_completed")
			downstream, err := base64.StdEncoding.DecodeString(payload["downstream_payload_b64"].(string))
			if err != nil {
				t.Fatalf("downstream_payload_b64 is invalid base64: %v", err)
			}
			if string(downstream) != test.downstream {
				t.Fatalf("downstream = %q, want %q", downstream, test.downstream)
			}
			if conn.written.String() != test.upstream {
				t.Fatalf("upstream written = %q, want %q", conn.written.String(), test.upstream)
			}
			if len(dialer.routes) != 1 || dialer.routes[0].ApplicationID != test.applicationID || dialer.routes[0].Host != test.host || dialer.routes[0].Port != test.port {
				t.Fatalf("opened routes = %+v, want %s %s:%d", dialer.routes, test.applicationID, test.host, test.port)
			}
			audit, ok := payload["audit"].(map[string]any)
			if !ok {
				t.Fatalf("audit = %#v, want object", payload["audit"])
			}
			if audit["metadata_only"] != true ||
				audit["application_id"] != test.applicationID ||
				audit["raw_payload_included"] != false ||
				audit["raw_ne_flow_included"] != false ||
				audit["raw_destination_ip_included"] != false ||
				audit["tls_material_included"] != false ||
				audit["certificate_material_included"] != false {
				t.Fatalf("audit = %+v, want metadata-only major protocol audit", audit)
			}
			for _, key := range []string{
				"runtime_installed_claimed",
				"flow_tunneled_claimed",
				"flow_denied_claimed",
				"real_tls_interception_claimed",
				"certificate_issuance_claimed",
				"production_private_app_enforcement_claimed",
			} {
				if payload[key] != false {
					t.Fatalf("%s = %v, want false", key, payload[key])
				}
			}
		})
	}
}

func TestRuntimeCopyRoundTripMajorProtocolTimeoutClosesConnection(t *testing.T) {
	routes, err := loadConnectorTCPRoutesFromProtectedAppMap(filepath.Join("testdata", "protected_app_map.json"))
	if err != nil {
		t.Fatalf("loadConnectorTCPRoutesFromProtectedAppMap returned error: %v", err)
	}
	body := validRuntimeCopyRoundTripRequest()
	body["request_id"] = "req_runtime_copy_ssh_timeout_m1455"
	body["application_id"] = "app_dummy_ssh"
	conn := newRuntimeCopyRoundTripBlockingConnection()
	dialer := &runtimeCopyRoundTripBlockingDialer{conn: conn}
	response := serveRuntimeCopyRoundTripWithRoutes(t, http.MethodPost, mustMarshalRuntimeCopyRoundTripBody(t, body), routes, dialer, 5*time.Millisecond)

	assertRuntimeCopyStatus(t, response, http.StatusGatewayTimeout, "round_trip_timeout")
	if len(dialer.routes) != 1 || dialer.routes[0].ApplicationID != "app_dummy_ssh" || dialer.routes[0].Host != "dummy-ssh.local" || dialer.routes[0].Port != 22 {
		t.Fatalf("opened routes = %+v, want ssh timeout route", dialer.routes)
	}
	if !conn.closed {
		t.Fatal("blocking major protocol connection was not closed on timeout")
	}
}

func TestRuntimeCopyRoundTripEmitsMetadataOnlyAudit(t *testing.T) {
	dialer := &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("phase2-private-app-response")}
	response := serveRuntimeCopyRoundTrip(t, http.MethodPost, validRuntimeCopyRoundTripBody(t), dialer, 100*time.Millisecond)

	payload := assertRuntimeCopyStatus(t, response, http.StatusOK, "round_trip_completed")
	audit, ok := payload["audit"].(map[string]any)
	if !ok {
		t.Fatalf("audit = %#v, want object", payload["audit"])
	}
	if audit["metadata_only"] != true {
		t.Fatalf("audit.metadata_only = %v, want true", audit["metadata_only"])
	}
	for _, key := range []string{
		"raw_payload_included",
		"raw_ne_flow_included",
		"raw_destination_ip_included",
		"host_user_material_included",
		"credentials_included",
		"token_included",
		"cookie_included",
		"session_id_included",
		"client_secret_included",
		"tls_material_included",
		"certificate_material_included",
		"device_identifier_included",
		"apple_identifier_included",
	} {
		if audit[key] != false {
			t.Fatalf("audit[%s] = %v, want false", key, audit[key])
		}
	}
	if audit["tenant_id"] != runtimeCopyRoundTripTestTenantID ||
		audit["request_id"] != "req_runtime_copy_m1188" ||
		audit["application_id"] != "app_dummy_https" {
		t.Fatalf("audit metadata = %+v, want tenant/request/application only", audit)
	}
}

func TestRuntimeCopyRoundTripDoesNotExpandClaims(t *testing.T) {
	for _, test := range []struct {
		name   string
		body   []byte
		status int
	}{
		{
			name:   "success",
			body:   validRuntimeCopyRoundTripBody(t),
			status: http.StatusOK,
		},
		{
			name: "failure",
			body: func() []byte {
				body := validRuntimeCopyRoundTripRequest()
				body["application_id"] = "app_unregistered_runtime_copy"
				return mustMarshalRuntimeCopyRoundTripBody(t, body)
			}(),
			status: http.StatusBadGateway,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dialer := &recordingTCPConnectionDialer{conn: newRecordingTCPConnection("phase2-private-app-response")}
			response := serveRuntimeCopyRoundTrip(t, http.MethodPost, test.body, dialer, 100*time.Millisecond)
			payload := decodeRuntimeCopyRoundTripResponse(t, response)
			if response.Code != test.status {
				t.Fatalf("status = %d payload=%+v, want %d", response.Code, payload, test.status)
			}
			for _, key := range []string{
				"runtime_installed_claimed",
				"flow_tunneled_claimed",
				"flow_denied_claimed",
				"real_tls_interception_claimed",
				"certificate_issuance_claimed",
				"production_private_app_enforcement_claimed",
			} {
				if payload[key] != false {
					t.Fatalf("%s = %v, want false", key, payload[key])
				}
			}
			if payload["runtime_overclaim_gate"] != "ok" || payload["flow_copy_overclaim_gate"] != "ok" {
				t.Fatalf("overclaim gates = %v/%v, want ok/ok", payload["runtime_overclaim_gate"], payload["flow_copy_overclaim_gate"])
			}
		})
	}
}

func serveRuntimeCopyRoundTrip(t *testing.T, method string, body []byte, dialer connectorTCPConnectionDialer, timeout time.Duration) *httptest.ResponseRecorder {
	t.Helper()
	return serveRuntimeCopyRoundTripWithRoutes(t, method, body, allowedConnectorTCPRoutes(), dialer, timeout)
}

func serveRuntimeCopyRoundTripWithRoutes(t *testing.T, method string, body []byte, routes []connectorTCPRoute, dialer connectorTCPConnectionDialer, timeout time.Duration) *httptest.ResponseRecorder {
	t.Helper()
	handler := runtimeCopyRoundTripHandler(runtimeCopyRoundTripHandlerConfig{
		TenantID: runtimeCopyRoundTripTestTenantID,
		Routes:   routes,
		Dialer:   dialer,
		Timeout:  timeout,
		Now:      fixedConnectorTestNow(),
	})
	request := httptest.NewRequest(method, runtimeCopyRoundTripPath, bytes.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func validRuntimeCopyRoundTripRequest() map[string]any {
	return map[string]any{
		"schema_version":       runtimeCopyRoundTripRequestSchema,
		"tenant_id":            runtimeCopyRoundTripTestTenantID,
		"request_id":           "req_runtime_copy_m1188",
		"application_id":       "app_dummy_https",
		"upstream_payload_b64": base64.StdEncoding.EncodeToString([]byte("phase2-client-runtime-copy")),
	}
}

func validRuntimeCopyRoundTripBody(t *testing.T) []byte {
	t.Helper()
	return mustMarshalRuntimeCopyRoundTripBody(t, validRuntimeCopyRoundTripRequest())
}

func mustMarshalRuntimeCopyRoundTripBody(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return body
}

func assertRuntimeCopyStatus(t *testing.T, response *httptest.ResponseRecorder, status int, category string) map[string]any {
	t.Helper()
	payload := decodeRuntimeCopyRoundTripResponse(t, response)
	if response.Code != status {
		t.Fatalf("status = %d payload=%+v, want %d", response.Code, payload, status)
	}
	if payload["category"] != category {
		t.Fatalf("category = %v, want %s; payload=%+v", payload["category"], category, payload)
	}
	if payload["audit_metadata_only_gate"] != "ok" || payload["secret_leak_gate"] != "ok" {
		t.Fatalf("metadata/secret gates = %v/%v, want ok/ok", payload["audit_metadata_only_gate"], payload["secret_leak_gate"])
	}
	return payload
}

func decodeRuntimeCopyRoundTripResponse(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response %q: %v", response.Body.String(), err)
	}
	return payload
}

func assertNoRuntimeCopyRouteOpened(t *testing.T, dialer *recordingTCPConnectionDialer) {
	t.Helper()
	if got := len(dialer.routes); got != 0 {
		t.Fatalf("opened routes = %+v, want none before validation/default-deny", dialer.routes)
	}
}

type runtimeCopyRoundTripBlockingDialer struct {
	routes []connectorTCPRoute
	conn   *runtimeCopyRoundTripBlockingConnection
}

func (dialer *runtimeCopyRoundTripBlockingDialer) OpenTCPConnection(ctx context.Context, route connectorTCPRoute) (io.ReadWriteCloser, error) {
	dialer.routes = append(dialer.routes, route)
	return dialer.conn, nil
}

type runtimeCopyRoundTripBlockingConnection struct {
	mu       sync.Mutex
	closed   bool
	closedCh chan struct{}
	once     sync.Once
}

func newRuntimeCopyRoundTripBlockingConnection() *runtimeCopyRoundTripBlockingConnection {
	return &runtimeCopyRoundTripBlockingConnection{closedCh: make(chan struct{})}
}

func (conn *runtimeCopyRoundTripBlockingConnection) Read(p []byte) (int, error) {
	<-conn.closedCh
	return 0, io.EOF
}

func (conn *runtimeCopyRoundTripBlockingConnection) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, errors.New("empty write")
	}
	return len(p), nil
}

func (conn *runtimeCopyRoundTripBlockingConnection) Close() error {
	conn.once.Do(func() {
		conn.mu.Lock()
		conn.closed = true
		conn.mu.Unlock()
		close(conn.closedCh)
	})
	return nil
}
