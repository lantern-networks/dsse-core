package device

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestApplyRiskSignal(t *testing.T) {
	s := NewStore()
	pb := model.PolicyBundle{TenantID: "t"}
	now := time.Now()
	if _, err := s.Register(model.Device{ID: "d1", TenantID: "t"}, pb, now); err != nil {
		t.Fatal(err)
	}

	// Manual high-risk marking -> high, metadata reflects it.
	dev, found, high, _ := s.ApplyRiskSignal("d1", model.RiskSignal{EntityType: "device", EntityID: "d1", Source: "manual_high_risk", Severity: "high", SuggestedAction: "revoke"}, now)
	if !found || !high {
		t.Fatalf("expected found+high, got found=%v high=%v", found, high)
	}
	if dev.Metadata["admin_high_risk"] != true || dev.Metadata["risk_state_severity"] != "high" {
		t.Fatalf("metadata not set: %+v", dev.Metadata)
	}

	// Risk LEVEL is driven by SEVERITY only: a medium signal is NOT high risk even with an isolate/block/revoke
	// action. And since only HIGH drives the emergency/ransomware overlay, a below-HIGH signal must NOT leave
	// enforcement-driving fields (recommended action / signal sources) behind.
	devM, _, h, _ := s.ApplyRiskSignal("d1", model.RiskSignal{EntityType: "device", EntityID: "d1", Source: "idp_risk", Severity: "medium", SuggestedAction: "isolate"}, now)
	if h || devM.Metadata["admin_high_risk"] != false {
		t.Fatalf("medium+isolate must NOT be high risk (severity drives level), got high=%v meta=%v", h, devM.Metadata["admin_high_risk"])
	}
	if _, ok := devM.Metadata["risk_recommended_action"]; ok {
		t.Fatalf("below-HIGH must not leave a recommended action driving enforcement, got %v", devM.Metadata["risk_recommended_action"])
	}
	if _, ok := devM.Metadata["risk_signal_sources"]; ok {
		t.Fatalf("below-HIGH must not leave signal sources driving enforcement, got %v", devM.Metadata["risk_signal_sources"])
	}

	// Escalate: HIGH records the driving fields (source + action) for the emergency overlay.
	devH, _, hh, _ := s.ApplyRiskSignal("d1", model.RiskSignal{EntityType: "device", EntityID: "d1", Source: "manual_high_risk", Severity: "high", SuggestedAction: "block"}, now)
	if !hh || devH.Metadata["admin_high_risk"] != true {
		t.Fatalf("severity=high should be high risk")
	}
	if devH.Metadata["risk_signal_sources"] == nil || devH.Metadata["risk_recommended_action"] != "block" {
		t.Fatalf("HIGH should record source+action, got sources=%v action=%v", devH.Metadata["risk_signal_sources"], devH.Metadata["risk_recommended_action"])
	}
	// ★ Footgun regression guard: a severity:none clear MUST fully de-escalate even when it REUSES
	// source=manual_high_risk AND carries a block action. Before the fix, admin_high_risk latched true (via source
	// OR action) and/or the source persisted in risk_signal_sources (riskEnforcementReasonCodeForRiskSource),
	// so the device stayed lateral-blocked forever — a real incident when clearing a mark.
	dev, _, high, _ = s.ApplyRiskSignal("d1", model.RiskSignal{EntityType: "device", EntityID: "d1", Source: "manual_high_risk", Severity: "none", SuggestedAction: "block"}, now)
	if high || dev.Metadata["admin_high_risk"] != false {
		t.Fatalf("severity:none must de-escalate regardless of source/action, got high=%v meta=%v", high, dev.Metadata["admin_high_risk"])
	}
	if _, ok := dev.Metadata["risk_signal_sources"]; ok {
		t.Fatalf("clear must drop risk_signal_sources (else the source keeps triggering the overlay), got %v", dev.Metadata["risk_signal_sources"])
	}
	if _, ok := dev.Metadata["risk_recommended_action"]; ok {
		t.Fatalf("clear must drop risk_recommended_action, got %v", dev.Metadata["risk_recommended_action"])
	}

	// De-escalation: a low-severity observe signal also clears high risk.
	dev, _, high, _ = s.ApplyRiskSignal("d1", model.RiskSignal{EntityType: "device", EntityID: "d1", Source: "idp_risk", Severity: "low", SuggestedAction: "observe"}, now)
	if high || dev.Metadata["admin_high_risk"] != false {
		t.Fatalf("low/observe should de-escalate, got high=%v meta=%v", high, dev.Metadata["admin_high_risk"])
	}

	// Absent device.
	if _, found, _, _ := s.ApplyRiskSignal("nope", model.RiskSignal{EntityType: "device", EntityID: "nope", Severity: "high"}, now); found {
		t.Fatalf("absent device should be not found")
	}
}
