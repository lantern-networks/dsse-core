package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

// TestDeviceGroupRiskFloorGatesEastWestPolicy is the end-to-end proof of "device-group risk -> policy control":
// a device assigned to a group whose risk FLOOR is high resolves to risk_state_severity=high (union model,
// via enrichDecisionRequestWithRisk), which makes an authored "deny SSH when risk>=high, else allow" east-west
// policy DENY that device; a device with no group stays below the gate and the lower-precedence allow wins;
// un-assigning the device (mirrors the console) drops the floor and it returns to allow. The floor is
// CONDITION-ONLY — it never sets AdminHighRisk / never revokes .
func TestDeviceGroupRiskFloorGatesEastWestPolicy(t *testing.T) {
	const now = "2026-07-22T00:00:00Z"

	led := enrolledinventory.NewLedger()
	if _, err := led.CreateGroup("hot", "t1", "high-risk verification group", "high", now); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := led.EnrollGroup("dev-hot", "t1", "hot", "", now); err != nil { // assigned to the high-floor group
		t.Fatalf("enroll dev-hot: %v", err)
	}
	if _, err := led.EnrollGroup("dev-plain", "t1", "", "", now); err != nil { // no group -> no floor
		t.Fatalf("enroll dev-plain: %v", err)
	}
	overlay := revocation.NewHighRiskOverlay() // no per-device marks: the group floor is the ONLY risk source

	// --- 1. floor resolution (the enforcement wiring under test) ---
	hot := enrichDecisionRequestWithRisk(model.DecisionRequest{DeviceID: "dev-hot"}, nil, overlay, led)
	plain := enrichDecisionRequestWithRisk(model.DecisionRequest{DeviceID: "dev-plain"}, nil, overlay, led)
	if hot.RiskStateSeverity != "high" {
		t.Fatalf("dev-hot risk_state_severity = %q, want %q (inherited group floor)", hot.RiskStateSeverity, "high")
	}
	if hot.AdminHighRisk {
		t.Fatal("dev-hot AdminHighRisk must stay false — the group floor is condition-only, it must not revoke")
	}
	if plain.RiskStateSeverity != "" {
		t.Fatalf("dev-plain risk_state_severity = %q, want empty (no group -> no floor)", plain.RiskStateSeverity)
	}

	// --- 2. policy control: "deny SSH when risk>=high, otherwise allow" (what an operator authors) ---
	rules := []decision.EastWestRule{
		{ID: "deny-high", Priority: 100, Protocols: []string{"ssh"}, Mode: decision.EastWestModeDeny,
			RiskSeverities: []string{"high", "critical"}}, // "high or higher", already expanded
		{ID: "allow-otherwise", Priority: 200, Protocols: []string{"ssh"}, Mode: decision.EastWestModeAllow},
	}
	winner := func(severity string) string {
		got, ok := decision.MatchedEastWestRule(rules, model.DecisionRequest{ServiceFamily: "ssh", RiskStateSeverity: severity})
		if !ok {
			t.Fatalf("no rule matched at severity %q", severity)
		}
		return got.ID
	}
	if id := winner(hot.RiskStateSeverity); id != "deny-high" { // dev-hot (floor high) is DENIED
		t.Fatalf("dev-hot (group floor high) hit %q, want deny-high", id)
	}
	if id := winner(plain.RiskStateSeverity); id != "allow-otherwise" { // dev-plain is ALLOWED
		t.Fatalf("dev-plain (no group) hit %q, want allow-otherwise", id)
	}

	// --- 3. un-assign the device (console: set group to none) -> floor gone -> back to allow ---
	if _, ok, _ := led.SetGroup("dev-hot", "", now); !ok {
		t.Fatal("unassign dev-hot failed")
	}
	after := enrichDecisionRequestWithRisk(model.DecisionRequest{DeviceID: "dev-hot"}, nil, overlay, led)
	if after.RiskStateSeverity != "" {
		t.Fatalf("after un-assign, dev-hot risk_state_severity = %q, want empty", after.RiskStateSeverity)
	}
	if id := winner(after.RiskStateSeverity); id != "allow-otherwise" {
		t.Fatalf("dev-hot after un-assign hit %q, want allow-otherwise", id)
	}
}

// TestDeviceGroupRiskFloorTakesMaxWithDeviceMark verifies the union is a MAX, not an override: a device with
// its own medium mark AND a high group floor resolves to high; with its own critical mark and a medium floor it
// stays critical (the device's higher mark wins). Neither direction lowers the effective risk.
func TestDeviceGroupRiskFloorTakesMaxWithDeviceMark(t *testing.T) {
	const now = "2026-07-22T00:00:00Z"
	led := enrolledinventory.NewLedger()
	if _, err := led.CreateGroup("mid", "t1", "", "medium", now); err != nil {
		t.Fatalf("create mid: %v", err)
	}
	if _, err := led.CreateGroup("high", "t1", "", "high", now); err != nil {
		t.Fatalf("create high: %v", err)
	}
	if _, err := led.EnrollGroup("d1", "t1", "high", "", now); err != nil { // floor high
		t.Fatalf("enroll d1: %v", err)
	}
	if _, err := led.EnrollGroup("d2", "t1", "mid", "", now); err != nil { // floor medium
		t.Fatalf("enroll d2: %v", err)
	}
	overlay := revocation.NewHighRiskOverlay()
	overlay.Mark("d1", "medium")   // device mark BELOW the floor -> floor wins (high)
	overlay.Mark("d2", "critical") // device mark ABOVE the floor -> device wins (critical)

	d1 := enrichDecisionRequestWithRisk(model.DecisionRequest{DeviceID: "d1"}, nil, overlay, led)
	d2 := enrichDecisionRequestWithRisk(model.DecisionRequest{DeviceID: "d2"}, nil, overlay, led)
	if d1.RiskStateSeverity != "high" {
		t.Fatalf("d1 (mark medium, floor high) = %q, want high (floor wins)", d1.RiskStateSeverity)
	}
	if d2.RiskStateSeverity != "critical" {
		t.Fatalf("d2 (mark critical, floor medium) = %q, want critical (device wins)", d2.RiskStateSeverity)
	}
}
