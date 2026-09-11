package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	endpointinventory "github.com/lantern-networks/dsse-core/endpointinventory"

	"github.com/lantern-networks/dsse-core/connector"
	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestAdminEndpointInventoryOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    EndpointInventoryEntry:",
		"    EndpointInventoryList:",
		"  /admin/endpoints:",
		"  /admin/endpoints/{endpoint_id}:",
		"admin.endpoints.read",
		"admin.endpoints.write",
		`$ref: "#/components/schemas/EndpointInventoryList"`,
		`$ref: "#/components/schemas/EndpointInventoryEntry"`,
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

func TestAdminEndpointInventoryAPIListsSeededDevices(t *testing.T) {
	devices := devicestore.NewStore()
	now := time.Date(2026, 6, 1, 1, 2, 3, 0, time.UTC)
	if _, err := devices.Register(model.Device{
		ID:                  "dev_inventory_seed_001",
		TenantID:            "tenant_lab_001",
		UserID:              "user_lab_001",
		Hostname:            "macbook-seed.local",
		OS:                  "macos",
		OSVersion:           "15.5",
		AgentVersion:        "0.1.0",
		DeviceTrustLevel:    "managed", // client-claimed; ignored on registration (review #18) — derived to "unknown" without posture signals
		PolicyBundleID:      "pb_lab_20260522_001",
		PolicyBundleVersion: "2026.05.22.001",
		Status:              "healthy",
		RegisteredAt:        now.Format(time.RFC3339),
		LastSeenAt:          now.Format(time.RFC3339),
		Metadata:            map[string]any{"source": "seed"},
	}, testEvaluator().PolicyBundle, now); err != nil {
		t.Fatalf("register seed device: %v", err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:   testEvaluator(),
		Registry:    connector.NewRegistry(),
		AdminAuth:   newAdminAuthStore(),
		DeviceStore: devices,
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/endpoints?limit=10", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var result endpointinventory.ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode endpoint list: %v", err)
	}
	if result.Count != 1 || result.Limit != 10 || len(result.Endpoints) != 1 {
		t.Fatalf("endpoint list = %#v, want seeded device endpoint", result)
	}
	got := result.Endpoints[0]
	// DeviceTrustLevel is "unknown": the registration's client-claimed "managed" is ignored (trust is
	// derived only from real posture signals, absent here), which is the review #18 hardening.
	if got.EndpointID != "dev_inventory_seed_001" || got.Source != "device_inventory" || got.MetadataKeyCount != 1 || got.DeviceTrustLevel != "unknown" {
		t.Fatalf("seeded endpoint = %#v, want sanitized device inventory entry", got)
	}
}

func TestAdminEndpointInventoryAPIUpsertThenDetailRead(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        newAdminAuthStore(),
		AdminAuditOutbox: outbox,
	})
	body := `{
		"endpoint_id":"dev_admin_endpoint_001",
		"tenant_id":"tenant_lab_001",
		"user_id":"user_lab_001",
		"hostname":"macbook-admin.local",
		"os":"macos",
		"os_version":"15.5",
		"agent_version":"0.2.0",
		"device_trust_level":"managed",
		"policy_bundle_id":"pb_lab_20260522_001",
		"policy_bundle_version":"2026.05.22.001",
		"status":"healthy",
		"metadata_key_count":2,
		"source":"admin"
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/endpoints", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var created endpointinventory.Entry
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created endpoint: %v", err)
	}
	if created.EndpointID != "dev_admin_endpoint_001" || created.TenantID != "tenant_lab_001" || created.Source != "admin" || created.UpdatedAt == nil {
		t.Fatalf("created endpoint = %#v, want normalized tenant endpoint", created)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/admin/endpoints/dev_admin_endpoint_001", nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want %d, body=%s", detailRec.Code, http.StatusOK, detailRec.Body.String())
	}
	var detail endpointinventory.Entry
	if err := json.Unmarshal(detailRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode endpoint detail: %v", err)
	}
	if detail.EndpointID != created.EndpointID || detail.Hostname != "macbook-admin.local" || detail.MetadataKeyCount != 2 {
		t.Fatalf("detail endpoint = %#v, want created endpoint metadata", detail)
	}
	if len(outbox.insertedAudits) != 1 || outbox.insertedAudits[0].EventType != "admin_endpoint_inventory_upserted" {
		t.Fatalf("outbox inserted audits = %#v, want endpoint inventory upsert", outbox.insertedAudits)
	}
	audit := outbox.insertedAudits[0]
	if audit.SourceIP != nil || audit.ActorUserID != nil {
		t.Fatalf("endpoint audit included raw source/user fields: %#v", audit)
	}
	if audit.Metadata["endpoint_metadata_recorded_scope"] != "none" || audit.Metadata["runtime_hot_reload"] != false {
		t.Fatalf("endpoint audit metadata = %#v, want non-secret admin boundary", audit.Metadata)
	}
}

func TestAdminEndpointInventoryAPIRejectsTenantMismatch(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		AdminAuth: newAdminAuthStore(),
	})
	body := `{"endpoint_id":"dev_other_001","tenant_id":"tenant_other_001","status":"healthy"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/endpoints", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "tenant_id") {
		t.Fatalf("status = %d body=%s, want tenant mismatch bad request", rec.Code, rec.Body.String())
	}
}

func TestAdminEndpointInventoryAPIRequiresWriteScopeForAPIToken(t *testing.T) {
	adminAuth := newAdminAuthStore()
	adminAuth.UpsertPrincipal(adminPrincipal{
		ID:        "admin_endpoint_reader_001",
		TenantID:  "tenant_lab_001",
		Subject:   "sub_endpoint_reader_001",
		Email:     "endpoint-reader@example.test",
		Roles:     []string{"admin"},
		IDPID:     "keycloak_lab",
		Status:    "active",
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	adminAuth.UpsertAPIToken(adminAPIToken{
		ID:                        "admin_token_endpoint_reader_001",
		TenantID:                  "tenant_lab_001",
		Name:                      "endpoint-reader-token",
		TokenHash:                 adminTokenHash("raw-endpoint-reader-token"),
		Roles:                     []string{"admin"},
		Scopes:                    []string{"admin.endpoints.read"},
		CreatedByAdminPrincipalID: "admin_endpoint_reader_001",
		CreatedAt:                 time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Status:                    "active",
	})
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  connector.NewRegistry(),
		AdminAuth: adminAuth,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/endpoints", strings.NewReader(`{"endpoint_id":"dev_scope_denied_001","status":"healthy"}`))
	req.Header.Set("authorization", "Bearer raw-endpoint-reader-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin api token scope admin.endpoints.write is required") {
		t.Fatalf("status = %d body=%s, want write scope denial", rec.Code, rec.Body.String())
	}
}
