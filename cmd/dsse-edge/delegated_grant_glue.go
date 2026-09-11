package main

import (
	delegatedgrant "github.com/lantern-networks/dsse-core/delegatedgrant"
)

// newDelegatedAccessGrantStore reads the FIFO bound from the environment (codename env name) and injects
// it into the extracted store, keeping the OSS package env-name-free.
func newDelegatedAccessGrantStore() *delegatedgrant.Store {
	return delegatedgrant.NewStore(inMemoryEventStoreCapacity())
}
