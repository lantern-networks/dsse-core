package main

import (
	"database/sql"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	delegatedgrant "github.com/lantern-networks/dsse-core/delegatedgrant"
	"strings"
)

// newDelegatedAccessGrantStore reads the admission bound from the environment (codename env name) and injects
// it into the extracted store, keeping the OSS package env-name-free.
func newDelegatedAccessGrantStore() *delegatedgrant.Store {
	return delegatedgrant.NewStore(inMemoryEventStoreCapacity())
}

func delegatedGrantPersisterForRole(value string, db *sql.DB, sourceURL string) (blobstore.Persister, error) {
	if strings.TrimSpace(sourceURL) != "" {
		if storeBackend(value) == "postgres" {
			return nil, fmt.Errorf("received delegated grants require a node-local file path or in-memory cache")
		}
		db = nil
	}
	return cpStateBlobPersister(value, db, "delegated_grants")
}
