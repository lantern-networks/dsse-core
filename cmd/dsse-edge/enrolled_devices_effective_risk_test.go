package main

import (
	"testing"
	"time"

	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

// TestEnrolledDeviceEffectiveRiskReflectsDeviceMetadata is the proof for the risk-display observability fix
// (backlog #2): the GET /admin/enrolled-devices "effective_risk" the Console renders is computed with the SAME
// enrichDecisionRequestWithRisk the decision path uses, so it can't read LOWER than enforcement. The specific
// gap it closes is DEVICE-STORE METADATA risk_state_severity — a source the old Console never fetched (it only
// overlaid the risk-signals map + group floor), so an operator could see "normal" while the decision saw "high".
func TestEnrolledDeviceEffectiveRiskReflectsDeviceMetadata(t *testing.T) {
	now := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	store := devicestore.NewStore()
	// A device whose ONLY risk source is its device-store metadata (NOT the high-risk overlay, NOT a group floor).
	if _, err := store.Register(model.Device{
		ID:       "dev-meta",
		TenantID: "t1",
		Metadata: map[string]any{"risk_state_severity": "high"},
	}, model.PolicyBundle{}, now); err != nil {
		t.Fatalf("register dev-meta: %v", err)
	}
	// A device with no risk at all — the control case an operator correctly reads as Normal.
	if _, err := store.Register(model.Device{ID: "dev-clean", TenantID: "t1"}, model.PolicyBundle{}, now); err != nil {
		t.Fatalf("register dev-clean: %v", err)
	}

	led := enrolledinventory.NewLedger()
	overlay := revocation.NewHighRiskOverlay() // empty: this is exactly what the Console's risk-signals map reflected

	// The effective_risk the handler emits = enrichDecisionRequestWithRisk(...).RiskStateSeverity.
	effective := func(id string) string {
		return enrichDecisionRequestWithRisk(
			model.DecisionRequest{DeviceID: id, TenantID: "t1"},
			store, overlay, led,
		).RiskStateSeverity
	}

	if got := effective("dev-meta"); got != "high" {
		t.Fatalf("dev-meta effective_risk = %q, want high — the metadata risk the Console previously missed", got)
	}
	if got := effective("dev-clean"); got != "" {
		t.Fatalf("dev-clean effective_risk = %q, want empty (no risk from any source)", got)
	}
}

// TestEnrolledDeviceEffectiveRiskMaxesMetadataWithGroupFloor confirms the emitted effective_risk composes the
// device-metadata risk with the group floor as a MAX (union model): a device carrying metadata medium in a group
// whose floor is high resolves to high; metadata critical with a medium floor stays critical (device wins).
func TestEnrolledDeviceEffectiveRiskMaxesMetadataWithGroupFloor(t *testing.T) {
	now := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	store := devicestore.NewStore()
	if _, err := store.Register(model.Device{ID: "d-mid", TenantID: "t1", Metadata: map[string]any{"risk_state_severity": "medium"}}, model.PolicyBundle{}, now); err != nil {
		t.Fatalf("register d-mid: %v", err)
	}
	if _, err := store.Register(model.Device{ID: "d-crit", TenantID: "t1", Metadata: map[string]any{"risk_state_severity": "critical"}}, model.PolicyBundle{}, now); err != nil {
		t.Fatalf("register d-crit: %v", err)
	}

	led := enrolledinventory.NewLedger()
	if _, err := led.CreateGroup("hot", "t1", "", "high", "2026-07-22T00:00:00Z"); err != nil {
		t.Fatalf("create group hot: %v", err)
	}
	if _, err := led.CreateGroup("mid", "t1", "", "medium", "2026-07-22T00:00:00Z"); err != nil {
		t.Fatalf("create group mid: %v", err)
	}
	if _, err := led.EnrollGroup("d-mid", "t1", "hot", "", "2026-07-22T00:00:00Z"); err != nil { // metadata medium, floor high
		t.Fatalf("enroll d-mid: %v", err)
	}
	if _, err := led.EnrollGroup("d-crit", "t1", "mid", "", "2026-07-22T00:00:00Z"); err != nil { // metadata critical, floor medium
		t.Fatalf("enroll d-crit: %v", err)
	}
	overlay := revocation.NewHighRiskOverlay()

	effective := func(id string) string {
		return enrichDecisionRequestWithRisk(model.DecisionRequest{DeviceID: id, TenantID: "t1"}, store, overlay, led).RiskStateSeverity
	}
	if got := effective("d-mid"); got != "high" {
		t.Fatalf("d-mid (metadata medium, floor high) effective_risk = %q, want high (floor lifts it)", got)
	}
	if got := effective("d-crit"); got != "critical" {
		t.Fatalf("d-crit (metadata critical, floor medium) effective_risk = %q, want critical (device wins)", got)
	}
}
