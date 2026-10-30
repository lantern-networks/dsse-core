package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/grantstore"
	"log"
	"time"
)

// One worker per running server, not per request/handler fixture. A shared-store
// mutation re-reads the authority under its transaction before pruning.
func maintainAuthGrants(ctx context.Context, store *grantstore.Store) {
	if store == nil {
		return
	}
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		cleanup, cancel := context.WithTimeout(ctx, 10*time.Second)
		n, err := store.PruneExpired(cleanup, time.Now())
		cancel()
		stats := store.RetentionStats()
		log.Printf("auth_grant_retention rows=%d snapshot_bytes=%d removed=%d saved=%t", stats.Rows, stats.SnapshotBytes, n, err == nil)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
