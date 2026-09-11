package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agenttelemetry"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestDeviceHeartbeatUsesCanonicalProvenIdentityAndJoinsConsole(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "shinnomac-mini", "tenant_a")
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := device.NewStore()
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer,
		Registry: connector.NewRegistry(), EnrolledLedger: ledger, DeviceStore: store,
		AdminAuth: newAdminAuthStore(), OperatorTenantID: "tenant_lab_001"})
	call := func(path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, provenDeviceRequest(http.MethodPost, path, "ShinnoMac-mini", body))
		return rec
	}
	// A first heartbeat after restart must rehydrate the ledger identity, even when the
	// certificate and URL use the original mixed-case hostname.
	rec := call("/devices/ShinnoMac-mini/heartbeat", `{"id":"ShinnoMac-mini","tenant_id":"tenant_a","agent_version":"0.3.0+current"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String())
	}
	if _, exists := store.Get("ShinnoMac-mini"); exists {
		t.Fatal("mixed-case duplicate persisted")
	}
	if d, exists := store.Get("shinnomac-mini"); !exists || d.AgentVersion != "0.3.0+current" {
		t.Fatalf("canonical heartbeat missing: %+v", d)
	}
	for _, request := range []struct{ path, body string }{
		{"/devices/somebody-else/heartbeat", `{"id":"ShinnoMac-mini","tenant_id":"tenant_a"}`},
		{"/devices/ShinnoMac-mini/heartbeat", `{"id":"somebody-else","tenant_id":"tenant_a"}`},
		{"/devices/register", `{"id":"somebody-else","tenant_id":"tenant_a"}`},
	} {
		if rec := call(request.path, request.body); rec.Code != http.StatusForbidden {
			t.Fatalf("spoof accepted: %d %s", rec.Code, rec.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/enrolled-devices", nil)
	req.Header.Set("X-Operate-Tenant", "tenant_a")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var body map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
		t.Fatalf("console: %d %s", rec.Code, rec.Body.String())
	}
	rows := body["devices"].([]any)
	if len(rows) != 1 {
		t.Fatalf("console rows: %+v", rows)
	}
	row := rows[0].(map[string]any)
	if row["identity"] != "shinnomac-mini" || row["agent_version"] != "0.3.0+current" || row["last_seen_at"] == nil {
		t.Fatalf("console lost heartbeat: %+v", row)
	}
}

func TestRuntimeIdentityJoinKeepsRecentVersionAndTenantBoundary(t *testing.T) {
	rows := []model.Device{
		{ID: "ShinnoMac-mini", TenantID: "tenant_a", AgentVersion: "0.3.0+new", LastSeenAt: "2026-09-09T05:00:00Z"},
		{ID: "shinnomac-mini", TenantID: "tenant_a", LastSeenAt: "2026-09-09T05:01:00Z"},
		{ID: "SHINNOMAC-MINI", TenantID: "tenant_a", AgentVersion: "0.3.0+old", LastSeenAt: "2026-09-09T04:00:00Z"},
		{ID: "ShinnoMac-mini", TenantID: "tenant_b", AgentVersion: "secret-other-tenant", LastSeenAt: "2026-09-09T06:00:00Z"},
		{ID: "ShinnoMac-mini", AgentVersion: "unassigned", LastSeenAt: "2026-09-09T07:00:00Z"},
	}
	for i := 0; i < len(rows); i++ {
		rows = append(rows[1:], rows[0])
		got := runtimeDevicesByIdentity(rows, "tenant_a")
		if len(got) != 1 || got["shinnomac-mini"].AgentVersion != "0.3.0+new" || got["shinnomac-mini"].LastSeenAt != "2026-09-09T05:01:00Z" {
			t.Fatalf("incorrect case/tenant join: %+v", got)
		}
	}
}

func TestUpdateIdentityJoinSelectsLatestOutcome(t *testing.T) {
	events := map[string]model.AgentUpdateEvent{
		"ShinnoMac-mini": {ID: "old", Timestamp: "2026-09-09T05:00:00Z", UpdateStatus: "installed"},
		"shinnomac-mini": {ID: "new", Timestamp: "2026-09-09T05:01:00Z", UpdateStatus: "failed"},
	}
	got := updateEventsByIdentity(events)
	if len(got) != 1 || got["shinnomac-mini"].ID != "new" || got["shinnomac-mini"].UpdateStatus != "failed" {
		t.Fatalf("new failure hidden by old success: %+v", got)
	}
}

func TestDeviceUpdatesCaseVariantIsOneDeviceWithHeartbeatVersion(t *testing.T) {
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "shinnomac-mini", "tenant_a")
	store := device.NewStore()
	_, err := store.Register(model.Device{ID: "ShinnoMac-mini", TenantID: "tenant_a", AgentVersion: "0.3.0+new", OS: "darwin"}, model.PolicyBundle{TenantID: "tenant_a"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerAgentDeviceUpdateRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		store, ledger, agenttelemetry.NewStore(), newPublishedAgentUpdateStore(), nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/agent/device-updates", nil)
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{}, adminIdentity{PrincipalID: "admin", TenantID: "tenant_a"}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var response agentDeviceUpdatesResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &response) != nil {
		t.Fatalf("response: %s", rec.Body.String())
	}
	if len(response.Devices) != 1 {
		t.Fatalf("split identity rows: %+v", response.Devices)
	}
	row := response.Devices[0]
	if row.DeviceID != "shinnomac-mini" || row.ReportedVersion != "0.3.0+new" || row.State != agentDeviceStateNeverReported {
		t.Fatalf("heartbeat must not imply a successful update: %+v", row)
	}
}
