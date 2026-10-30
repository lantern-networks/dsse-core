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

	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// TestDecisionEvaluateEnrichesRiskFromDeviceRiskMetadata pins that a device's stored risk state reaches the
// decision request (so POLICY can match on it) — and that it does NOT, by itself, deny. The hardcoded
// risk-enforcement overlay that used to deny here was removed; risk-based authorization is an operator policy
// decision. See
func TestDecisionEvaluateEnrichesRiskFromDeviceRiskMetadata(t *testing.T) {
	logDir := t.TempDir()
	writer, err := logs.NewWriter(logDir)
	if err != nil {
		t.Fatalf("NewWriter returned error: %v", err)
	}
	evaluator := testEvaluatorWithPolicies([]model.Policy{
		{
			ID:       "pol_lab_postgres_allow_001",
			TenantID: "tenant_lab_001",
			Priority: 100,
			Conditions: map[string]any{
				"actor_type":     "human",
				"application_id": "app_dummy_postgres",
				"service_family": "database",
			},
			Action: model.PolicyAction{Decision: "allow"},
			Status: "active",
		},
	})
	deviceStore := devicestore.NewStore()
	_, err = deviceStore.Register(model.Device{
		ID:               "dev_lab_risk_001",
		TenantID:         "tenant_lab_001",
		UserID:           "user_lab_001",
		DeviceTrustLevel: "managed",
	}, evaluator.PolicyBundle, time.Now())
	if err != nil {
		t.Fatalf("register device: %v", err)
	}
	riskNow := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	riskStateID := "risk_dev_lab_risk_001_20260722T000000Z"
	if _, found, _, err := deviceStore.ApplyRiskSignal("dev_lab_risk_001", model.RiskSignal{
		EntityType: "device", EntityID: "dev_lab_risk_001", Severity: "high",
		Source: "agent_tamper", SuggestedAction: "apply_ransomware_protection_mode",
	}, riskNow); err != nil || !found {
		t.Fatalf("apply device risk: found=%t err=%v", found, err)
	}
	handler := newServerWithConfig(serverConfig{
		Evaluator:   evaluator,
		Writer:      writer,
		DeviceStore: deviceStore,
	})

	req := httptest.NewRequest(http.MethodPost, "/decisions/evaluate", strings.NewReader(`{
		"tenant_id":"tenant_lab_001",
		"user_id":"user_lab_001",
		"device_id":"dev_lab_risk_001",
		"application_id":"app_dummy_postgres",
		"application_sensitivity":"high",
		"service_family":"database",
		"destination_port":5432,
		"protocol":"tcp"
	}`))
	req.Header.Set("content-type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("evaluate status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var dec model.AccessDecision
	if err := json.Unmarshal(rec.Body.Bytes(), &dec); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	// Risk alone must not deny — the matched operator policy (allow) governs.
	if dec.Decision != "allow" {
		t.Fatalf("decision = %q, want allow (device risk must not auto-deny)", dec.Decision)
	}
	// ...but the risk state must still be ENRICHED onto the decision, because that is what a risk-gated policy
	// condition matches against. Losing this would make risk unusable from policy.
	if dec.RiskStateID == nil || *dec.RiskStateID != riskStateID {
		t.Fatalf("risk_state_id = %#v, want %s", dec.RiskStateID, riskStateID)
	}
	// The removed overlay's vocabulary must not appear on the wire any more.
	for _, code := range []string{"ransomware_protection_mode_active", "risk_state_recommended_emergency_block"} {
		if containsString(dec.ReasonCodes, code) {
			t.Fatalf("reason_codes = %v, must not contain the removed overlay code %s", dec.ReasonCodes, code)
		}
	}
	if dec.Metadata["risk_state_id"] != riskStateID {
		t.Fatalf("metadata risk_state_id = %v, want %s", dec.Metadata["risk_state_id"], riskStateID)
	}

	accessLog, err := os.ReadFile(filepath.Join(logDir, "access.log.jsonl"))
	if err != nil {
		t.Fatalf("read access log: %v", err)
	}
	// The risk state must remain VISIBLE in the audit trail even though it no longer denies — an operator has
	// to be able to see that a decision was made for a high-risk device, and a risk-gated policy needs the same
	// fields to match on.
	for _, want := range []string{`"risk_state_severity":"high"`, `"risk_state_id":"` + riskStateID + `"`, `"agent_tamper"`} {
		if !strings.Contains(string(accessLog), want) {
			t.Fatalf("access log = %s, want %s", string(accessLog), want)
		}
	}
}
