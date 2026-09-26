package main

import (
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/seatallocation"
	"log"
)

func mustLoadSeatAllocations(store *seatallocation.Store, p blobstore.Persister) {
	if err := store.SetPersister(p); err != nil {
		log.Fatalf("seat allocations: invalid or unavailable saved configuration")
	}
}
