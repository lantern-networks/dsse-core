package main

import "github.com/lantern-networks/dsse-core/revocation"

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
