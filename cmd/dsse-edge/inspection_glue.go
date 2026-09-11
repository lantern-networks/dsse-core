package main

import (
	inspection "github.com/lantern-networks/dsse-core/inspection"
)

// newInspectionEventStore reads the FIFO bound from the environment (codename env name) and injects it
// into the extracted store, keeping the OSS package env-name-free.
func newInspectionEventStore() *inspection.Store {
	return inspection.NewStore(inMemoryEventStoreCapacity())
}
