package main

import (
	"context"
	"log"
	"time"
)

func meshWriteContext(ctx context.Context) context.Context {
	if _, ok := ctx.Value(cpWriteLeaseKey{}).(cpWriteLease); ok {
		return ctx
	}
	return captureCPWriteLease(ctx)
}
func meshLeaseCurrent(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	lease, ok := ctx.Value(cpWriteLeaseKey{}).(cpWriteLease)
	if !ok {
		return true
	}
	return lease.epoch != 0 && lease.elector.IsLeader() && lease.elector.leaderSince.Load() == lease.epoch
}

// Startup happens before election. Reload the shared queue on each new term,
// including promotion of an already-running standby. Failed reads retry without
// consuming the term. Workers keep that term through every retry and ACK.
func (s revocationMeshSource) resumeOnLeadership(ctx context.Context) {
	ticker := time.NewTicker(cpLeaderAcquireInterval)
	defer ticker.Stop()
	var resumed int64
	for {
		leaseCtx := meshWriteContext(ctx)
		lease, ok := leaseCtx.Value(cpWriteLeaseKey{}).(cpWriteLease)
		if ok && meshLeaseCurrent(leaseCtx) && lease.epoch != resumed {
			if n, err := s.resumePendingContext(leaseCtx); err != nil {
				log.Printf("revocation mesh outbox: leadership resume unavailable; will retry")
			} else {
				resumed = lease.epoch
				log.Printf("revocation mesh outbox: resumed %d pending deliveries for current leadership", n)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
