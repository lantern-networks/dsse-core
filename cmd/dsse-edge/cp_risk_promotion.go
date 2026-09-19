package main

import (
	"fmt"
	"net/http"

	"github.com/lantern-networks/dsse-core/revocation"
)

// Configure once before Start, after startup attribution has finished. Admission
// preparation stays in front of risk preparation; neither is advertised as ready
// when the other fails. This is not a transaction spanning the two stores.
func configureRiskPromotion(e *cpLeaderElector, backend string, risk *revocation.HighRiskOverlay) {
	if e == nil || risk == nil || storeBackend(backend) != "postgres" {
		return
	}
	previous := e.prepareLeadership
	e.prepareLeadership = func() error {
		if previous != nil {
			if err := previous(); err != nil {
				return err
			}
		}
		return risk.ReloadFromStore()
	}
}

// A standby refreshes risk during promotion, not on every read. Its healthy
// snapshot can therefore be older than the authority's device and user state.
func riskReadRefusedOnAStandby(w http.ResponseWriter) bool {
	if !edgeIsControlPlane || cpLeaderElectorInstance == nil || cpLeaderElectorInstance.IsLeader() {
		return false
	}
	writeError(w, http.StatusConflict, fmt.Errorf("this control plane does not hold leadership; risk state is not authoritative here. Retry through the active management server"))
	return true
}
