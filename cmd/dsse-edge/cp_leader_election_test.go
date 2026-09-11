package main

import (
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// TestCPLeaderElectorNilIsAlwaysLeader: no election configured (single-node/dev) => always leader.
func TestCPLeaderElectorNilIsAlwaysLeader(t *testing.T) {
	var e *cpLeaderElector
	if !e.IsLeader() {
		t.Fatal("a nil elector must report IsLeader()==true (single-node)")
	}
	e.Start() // no-op, must not panic
	e.Stop()  // no-op, must not panic
}

// TestCPLeaderElectorSingleLeaderAndFailover: exactly one of two contenders holds leadership; when it releases,
// the standby takes over. Drives tick directly (no timed loop) for determinism. Gated on a real Postgres.
func TestCPLeaderElectorSingleLeaderAndFailover(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	e1, err := newCPLeaderElector(dsn)
	if err != nil {
		t.Fatalf("e1: %v", err)
	}
	defer func() { e1.release(); _ = e1.db.Close() }()
	e2, err := newCPLeaderElector(dsn)
	if err != nil {
		t.Fatalf("e2: %v", err)
	}
	defer func() { e2.release(); _ = e2.db.Close() }()

	e1.tick() // e1 acquires the lock
	if !e1.IsLeader() {
		t.Fatal("e1 should have acquired leadership")
	}
	e2.tick() // e2 cannot acquire while e1 holds it
	if e2.IsLeader() {
		t.Fatal("two leaders at once — mutual exclusion broken")
	}

	e1.release() // active steps down (graceful) -> lock free
	e2.tick()    // standby takes over
	if !e2.IsLeader() {
		t.Fatal("standby did not acquire leadership after the active released")
	}
	if e1.IsLeader() {
		t.Fatal("released node still reports leader")
	}
}
