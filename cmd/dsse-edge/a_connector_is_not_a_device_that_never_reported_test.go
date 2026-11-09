package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agenttelemetry"
	"github.com/lantern-networks/dsse-core/connector"
	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
)

// Acceptance A, third run: one Windows device and one connector read "1/2 devices have reported an outcome".
// The connector is in the ledger, as it should be, and is not an agent this lane updates.
func TestUpdateCoverageDoesNotCountAConnectorAsASilentDevice(t *testing.T) {
	const tenant = "tenant_a"
	ledger := enrolledinventory.NewLedger()
	mustEnroll(t, ledger, "win-device-1", tenant)
	mustEnroll(t, ledger, "conn-hq-1", tenant)
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-hq-1", TenantID: tenant,
		PrivateBaseURL: "http://connector.internal", Status: "healthy"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	telemetry := agenttelemetry.NewStore()
	if err := telemetry.RecordUpdate(context.Background(), model.AgentUpdateEvent{ID: "aue_1", TenantID: tenant,
		DeviceID: "win-device-1", UpdateStatus: "installed", Timestamp: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}

	answer := func(reg connectorRegistryStore) map[string]any {
		mux := http.NewServeMux()
		registerAgentDeviceUpdateRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
			devicestore.NewStore(), ledger, telemetry, newPublishedAgentUpdateStore(), nil, nil, nil, nil, reg)
		req := httptest.NewRequest(http.MethodGet, "/admin/agent/device-updates", nil)
		req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{},
			adminIdentity{PrincipalID: "adm_test", TenantID: tenant, AuthMethod: "admin_session"}))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	// The control: without the registry, this is the reading the screen showed.
	control := answer(nil)["coverage"].(map[string]any)
	if control["devices"] != float64(2) || control["reported"] != float64(1) {
		t.Fatalf("the control does not reproduce 1/2: %v", control)
	}

	body := answer(registry)
	coverage := body["coverage"].(map[string]any)
	if coverage["devices"] != float64(1) || coverage["reported"] != float64(1) || coverage["never_reported"] != float64(0) {
		t.Fatalf("the connector is still counted as a device: %v", coverage)
	}
	if coverage["connectors"] != float64(1) {
		t.Fatalf("the withheld connector is not counted: %v", coverage)
	}
	raw, _ := json.Marshal(body["devices"])
	if strings.Contains(string(raw), "conn-hq-1") {
		t.Fatalf("the connector is a row on the device update view: %s", raw)
	}
}
