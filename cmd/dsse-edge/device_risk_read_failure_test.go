package main

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func riskReadFailureStore() *authCountingDeviceStore {
	return &authCountingDeviceStore{
		deviceRuntimeStore: devicestore.NewStore(),
		device:             model.Device{ID: "risk-device", TenantID: "tenant_lab_001", Metadata: map[string]any{"risk_state_severity": "high"}},
	}
}

func riskReadFailurePolicies() []model.Policy {
	return []model.Policy{
		{ID: "deny-high-risk", TenantID: "tenant_lab_001", Status: "active", Priority: 10, Conditions: map[string]any{"risk_state_severity": []any{"high", "critical"}}, Action: model.PolicyAction{Decision: "deny"}},
		{ID: "allow-otherwise", TenantID: "tenant_lab_001", Status: "active", Priority: 100, Action: model.PolicyAction{Decision: "allow"}},
	}
}

func TestDecisionEvaluateRejectsDeviceRiskInventoryReadFailure(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	store := riskReadFailureStore()
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluatorWithPolicies(riskReadFailurePolicies()), Writer: writer, DeviceStore: store})
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(`{"tenant_id":"tenant_lab_001","device_id":"risk-device","application_id":"risk-app"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if got := request(); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"decision":"deny"`) {
		t.Fatalf("healthy device risk did not select deny: status=%d body=%s", got.Code, got.Body.String())
	}
	store.err = errors.New("inventory unavailable")
	if got := request(); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("inventory read failure must stop policy evaluation, got status=%d body=%s", got.Code, got.Body.String())
	}
}

func TestDecisionEvaluateWithoutTenantRejectsClosedPostgresInventory(t *testing.T) {
	db, err := sql.Open("postgres", "host=127.0.0.1 port=1 sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	h := newServerWithConfig(serverConfig{
		Evaluator: testEvaluatorWithPolicies(riskReadFailurePolicies()), Writer: writer,
		DeviceStore: &postgresDeviceInventoryStore{DB: db},
	})
	r := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(`{"device_id":"risk-device","application_id":"risk-app"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unscoped inventory read failure must stop policy evaluation: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDeviceRiskCheckedLookupKeepsMissingAndLegacyMemorySemantics(t *testing.T) {
	store := devicestore.NewStore()
	req, err := enrichDecisionRequestWithRiskChecked(model.DecisionRequest{TenantID: "tenant_lab_001", DeviceID: "missing"}, store, nil, nil)
	if err != nil || req.RiskStateSeverity != "" {
		t.Fatalf("missing device is not an inventory failure: req=%+v err=%v", req, err)
	}
	if _, err := store.Register(model.Device{ID: "risk-device", TenantID: "tenant_lab_001", Metadata: map[string]any{"risk_state_severity": "high"}}, model.PolicyBundle{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, found, _, err := store.ApplyRiskSignal("risk-device", model.RiskSignal{EntityType: "device", EntityID: "risk-device", Severity: "high", Source: "manual_high_risk"}, time.Now()); err != nil || !found {
		t.Fatalf("apply high-risk signal: found=%t err=%v", found, err)
	}
	req, err = enrichDecisionRequestWithRiskChecked(model.DecisionRequest{DeviceID: "risk-device"}, store, nil, nil)
	if err != nil || req.TenantID != "tenant_lab_001" || req.RiskStateSeverity != "high" {
		t.Fatalf("legacy memory lookup lost the discovered tenant or risk: req=%+v err=%v", req, err)
	}
}

func TestSWGEgressRejectsDeviceRiskInventoryReadFailure(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	store := riskReadFailureStore()
	upstreamCalls := 0
	h := newEdgeSWGHTTPEgressHandler(edgeSWGHTTPEgressHandlerConfig{
		Evaluator: decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant_lab_001"}, Policies: riskReadFailurePolicies()},
		Writer:    writer, DeviceStore: store, DeviceAuthenticatedInProcess: true,
		DecisionStore: newAccessDecisionStore(), InspectionEvents: newInspectionEventStore(),
		ProxyClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			upstreamCalls++
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		})},
	})
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, edgeplane.EdgeSWGHTTPEgressPath, nil)
		r.Header.Set(edgeplane.EdgeSWGHTTPEgressTargetURLHeader, "https://risk-app.example/")
		r = r.WithContext(edgeplane.WithTransportDevice(edgeplane.WithFlowTenant(r.Context(), "tenant_lab_001"), "risk-device"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if got := request(); got.Code != http.StatusForbidden {
		t.Fatalf("healthy high-risk device should be denied, got status=%d body=%s", got.Code, got.Body.String())
	}
	store.err = errors.New("inventory unavailable")
	if got := request(); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("inventory read failure must stop egress, got status=%d body=%s", got.Code, got.Body.String())
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstream reached %d times despite risk denial/outage", upstreamCalls)
	}
}

func TestSteerInitialDecisionRejectsInventoryReadFailure(t *testing.T) {
	store := riskReadFailureStore()
	store.err = errors.New("inventory unavailable")
	_, err := enrichSteerDeviceRequest(model.DecisionRequest{TenantID: "tenant_lab_001", DeviceID: "risk-device"}, "managed", nil, store, nil, nil)
	if err == nil {
		t.Fatal("initial steer decision ignored inventory read failure")
	}
	if store.reads != 1 {
		t.Fatalf("initial steer read inventory %d times, want once", store.reads)
	}
}

func TestAdminEnrolledRiskDoesNotDisplayHealthyOnInventoryReadFailure(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("risk-device", "tenant_lab_001", "", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	store := riskReadFailureStore()
	store.err = errors.New("inventory unavailable")
	h := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, DeviceStore: store, EnrolledLedger: ledger,
		Registry: connector.NewRegistry(), AdminAuth: newAdminAuthStore(), OperatorTenantID: "tenant_lab_001",
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/enrolled-devices", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("risk column must be unavailable rather than empty on inventory failure: status=%d body=%s", w.Code, w.Body.String())
	}
}
