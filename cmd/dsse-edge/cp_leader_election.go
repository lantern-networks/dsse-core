package main

import (
	"context"
	"database/sql"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// CP leader election via a Postgres SESSION-level advisory lock (reuses the HA Postgres; no separate etcd needed).
// The active CP holds pg_advisory_lock on a DEDICATED connection; because a session advisory lock is released the
// instant its session ends, a CP crash — or a Postgres failover that kills the connection — auto-releases the lock
// (fencing), and the warm standby acquires it on its next attempt and becomes leader. Only the leader runs the
// non-idempotent background workers and is routed to (HAProxy health-checks GET /leader). See
//  A nil elector (no -postgres-dsn, single-node/dev) is always leader.

// cpLeaderAdvisoryLockKey is the fixed 64-bit key for the CP-leader advisory lock. Arbitrary but stable so both
// CPs contend on the SAME lock. ("DSSECPLD" as ascii-ish bytes.)
const cpLeaderAdvisoryLockKey int64 = 0x4453_5345_4350_4c44

const (
	cpLeaderAcquireInterval = 3 * time.Second // how often a standby retries to acquire leadership
	cpLeaderPingInterval    = 3 * time.Second // how often the leader verifies it still holds the lock
)

// cpLeaderElectorInstance is the process-wide elector, set in main. Package-global (like cpStateBlobDB) because
// the /leader HTTP handler is registered in newServerWithConfig, a different function. nil = always leader.
var cpLeaderElectorInstance *cpLeaderElector

type cpLeaderElector struct {
	db       *sql.DB
	isLeader atomic.Bool
	// leaderSince is when this node most recently BECAME the leader, in unix nanoseconds; zero when it is not.
	//
	// ★★★ IT EXISTS BECAUSE A NEWLY-PROMOTED AUTHORITY KNOWS NOTHING AND SAYS EVERYTHING (2026-08-25,
	// measured). The fleet view is "whoever is reporting now", and reports arrive at the LEADER. Fifteen
	// seconds after a failover, two of four Edges had re-reported and /admin/fleet/config-status answered
	//
	//	2 edges, in_sync: true
	//
	// — the whole fleet agreeing, computed over half of it. Nothing was wrong with the store; what was
	// missing is that "this is the fleet" and "this is who has managed to reach me since I took over" are
	// different sentences, and only one of them was being said. See fleetViewHasFormed.
	leaderSince atomic.Int64
	mu          sync.Mutex
	conn        *sql.Conn // the dedicated connection holding the advisory lock while leader; nil when standby
	stop        chan struct{}
	stopped     chan struct{}
	// Installed before Start. It refreshes shared revocation state while the
	// advisory lock is held but /leader and administrative writes remain closed.
	prepareLeadership func() error
}

// newCPLeaderElector opens a small dedicated pool for the leader lock. Returns nil when dsn is empty (single-node
// / dev): a nil elector reports IsLeader==true so everything runs as before.
func newCPLeaderElector(dsn string) (*cpLeaderElector, error) {
	if dsn == "" {
		return nil, nil
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	// The advisory lock is held by ONE connection; keep the pool tiny and never recycle a live connection under us.
	db.SetMaxOpenConns(2)
	db.SetConnMaxLifetime(0)
	return &cpLeaderElector{db: db, stop: make(chan struct{}), stopped: make(chan struct{})}, nil
}

// IsLeader reports whether this node currently holds CP leadership. A nil elector (no election configured) is
// always leader.
func (e *cpLeaderElector) IsLeader() bool {
	if e == nil {
		return true
	}
	return e.isLeader.Load()
}

// Start runs the election loop until Stop. It acquires leadership as soon as the lock is free and steps down the
// instant its holding connection dies.
func (e *cpLeaderElector) Start() {
	if e == nil {
		return
	}
	go e.loop()
}

func (e *cpLeaderElector) loop() {
	defer close(e.stopped)
	t := time.NewTicker(cpLeaderAcquireInterval)
	defer t.Stop()
	e.tick()
	for {
		select {
		case <-e.stop:
			e.release()
			return
		case <-t.C:
			e.tick()
		}
	}
}

func (e *cpLeaderElector) tick() {
	if e.isLeader.Load() {
		// Verify the lock-holding connection is still alive; a dead connection = lost session = lost lock.
		e.mu.Lock()
		conn := e.conn
		e.mu.Unlock()
		if conn == nil {
			e.isLeader.Store(false)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), cpLeaderPingInterval)
		err := conn.PingContext(ctx)
		cancel()
		if err != nil {
			log.Printf("cp_leader: lost the lock connection (%v) — stepping down", err)
			e.mu.Lock()
			_ = e.conn.Close()
			e.conn = nil
			e.mu.Unlock()
			e.isLeader.Store(false)
		}
		return
	}
	// Standby: try to acquire the lock on a fresh dedicated connection.
	ctx, cancel := context.WithTimeout(context.Background(), cpLeaderAcquireInterval)
	defer cancel()
	conn, err := e.db.Conn(ctx)
	if err != nil {
		return // Postgres unreachable (e.g. mid-failover); retry next tick.
	}
	var got bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", cpLeaderAdvisoryLockKey).Scan(&got); err != nil || !got {
		_ = conn.Close() // returning to the pool is fine — we did NOT acquire the lock
		return
	}
	e.mu.Lock()
	e.conn = conn // hold this connection (and thus the lock) for as long as we are leader
	e.mu.Unlock()
	if e.prepareLeadership != nil {
		if err := e.prepareLeadership(); err != nil {
			log.Printf("cp_leader: shared revocation state could not be prepared; leadership remains unavailable")
			e.release()
			return
		}
		// A slow read may outlive the connection that held the lock. Do not
		// publish leadership on a connection already known to be unavailable.
		checkCtx, checkCancel := context.WithTimeout(context.Background(), cpLeaderPingInterval)
		err := conn.PingContext(checkCtx)
		checkCancel()
		if err != nil {
			log.Printf("cp_leader: lock connection unavailable after revocation refresh")
			e.release()
			return
		}
	}
	e.leaderSince.Store(time.Now().UnixNano())
	e.isLeader.Store(true)
	log.Printf("cp_leader: acquired leadership (advisory lock %d)", cpLeaderAdvisoryLockKey)
}

// release drops leadership on graceful shutdown so a peer takes over promptly instead of waiting for the TTL.
func (e *cpLeaderElector) release() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _ = e.conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", cpLeaderAdvisoryLockKey)
		cancel()
		_ = e.conn.Close()
		e.conn = nil
	}
	e.isLeader.Store(false)
}

// Stop ends the election loop and releases the lock. Safe on a nil elector.
func (e *cpLeaderElector) Stop() {
	if e == nil {
		return
	}
	close(e.stop)
	<-e.stopped
	_ = e.db.Close()
}

// LeaderSince is when this node most recently became the leader. The zero time means it is not the leader, or
// that no election is configured — a single node has been the authority for as long as it has been running,
// which is what its own start time already says.
func (e *cpLeaderElector) LeaderSince() time.Time {
	if e == nil {
		return time.Time{}
	}
	if !e.isLeader.Load() {
		return time.Time{}
	}
	ns := e.leaderSince.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}
