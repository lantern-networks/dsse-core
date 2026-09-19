package main

import "github.com/lantern-networks/dsse-core/seatallocation"

func configureSeatPromotion(e *cpLeaderElector, backend string, seats *seatallocation.Store) {
	if e == nil || seats == nil || storeBackend(backend) != "postgres" {
		return
	}
	previous := e.prepareLeadership
	e.prepareLeadership = func() error {
		if previous != nil {
			if err := previous(); err != nil {
				return err
			}
		}
		return seats.ReloadFromStore()
	}
}
