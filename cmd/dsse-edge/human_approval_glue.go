package main

import (
	humanapproval "github.com/lantern-networks/dsse-core/humanapproval"
)

// newHumanApprovalEventStore reads the FIFO bound from the environment (codename env name) and injects
// it into the extracted store, keeping the OSS package env-name-free.
func newHumanApprovalEventStore() *humanapproval.Store {
	return humanapproval.NewStore(inMemoryEventStoreCapacity())
}
