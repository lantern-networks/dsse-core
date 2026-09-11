package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

// The decision-request enrichment consults the shared overlay so a device marked high-risk on the CP is
// treated high-risk by EVERY node — even one whose local device store never saw the device (the whole point).
func TestEnrichDecisionRequestConsultsHighRiskOverlay(t *testing.T) {
	o := revocation.NewHighRiskOverlay()
	o.Mark("dev-x", "high")

	// deviceStore nil + device unknown locally: the overlay alone must drive AdminHighRisk.
	req := enrichDecisionRequestWithDeviceRisk(model.DecisionRequest{DeviceID: "dev-x"}, nil, o)
	if !req.AdminHighRisk {
		t.Fatalf("a device in the shared high-risk overlay must set AdminHighRisk even with no local device record")
	}
	if req.RiskStateSeverity != "high" {
		t.Fatalf("severity should be filled from the overlay, got %q", req.RiskStateSeverity)
	}

	// A device NOT in the overlay (and no local record) stays clean.
	clean := enrichDecisionRequestWithDeviceRisk(model.DecisionRequest{DeviceID: "dev-clean"}, nil, o)
	if clean.AdminHighRisk {
		t.Fatalf("a device not in the overlay must not be marked high-risk")
	}
}
