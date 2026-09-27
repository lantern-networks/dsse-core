package main

import "github.com/lantern-networks/dsse-core/enrolledinventory"

// Configure before Start. Every earlier preparation must succeed as well;
// inventory is not ready merely because the lock has been acquired.
func configureInventoryPromotion(e *cpLeaderElector, backend string, ledger *enrolledinventory.Ledger) {
	if e == nil || ledger == nil || storeBackend(backend) != "postgres" {
		return
	}
	previous := e.prepareLeadership
	e.prepareLeadership = func() error {
		if previous != nil {
			if err := previous(); err != nil {
				return err
			}
		}
		_, err := ledger.ReloadFromStore()
		return err
	}
}

// The leadership check and read must be in the same critical section as tick.
// Otherwise a slow standby read can overwrite an already promoted author's write.
func (e *cpLeaderElector) refreshStandbyInventory(ledger *enrolledinventory.Ledger) (bool, error) {
	if e == nil || ledger == nil {
		return false, nil
	}
	e.stateRefreshMu.Lock()
	defer e.stateRefreshMu.Unlock()
	if e.IsLeader() {
		return false, nil
	}
	return ledger.ReloadFromStore()
}
