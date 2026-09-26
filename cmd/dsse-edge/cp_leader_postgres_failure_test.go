package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/lib/pq"
)

func postgresFailureElectors(t *testing.T) (*cpLeaderElector, *cpLeaderElector) {
	t.Helper()
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN is not set")
	}
	a, err := newCPLeaderElector(dsn)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newCPLeaderElector(dsn)
	if err != nil {
		a.db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { a.release(); b.release(); a.db.Close(); b.db.Close() })
	return a, b
}
func TestPostgresLeaderReleaseDiscardsFailedUnlockSession(t *testing.T) {
	a, b := postgresFailureElectors(t)
	a.tick()
	if !a.IsLeader() {
		t.Fatal("initial election failed")
	}
	b.tick()
	if b.IsLeader() {
		t.Fatal("two leaders")
	}
	// Put the dedicated session into a PostgreSQL error state. Unlock now fails
	// with 25P02 but the connection itself remains healthy and still owns the lock.
	// This is fault injection, not a transaction issued by the production elector.
	if _, err := a.conn.ExecContext(context.Background(), "BEGIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.conn.ExecContext(context.Background(), "SELECT 1/0"); err == nil {
		t.Fatal("fault was not injected")
	}
	_, err := a.conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", cpLeaderAdvisoryLockKey)
	var pgErr *pq.Error
	if !errors.As(err, &pgErr) || pgErr.Code != "25P02" {
		t.Fatalf("expected live-session SQL failure: %v", err)
	}
	a.release()
	if a.IsLeader() {
		t.Fatal("released node still advertised")
	}
	b.tick()
	if !b.IsLeader() {
		t.Fatal("failed unlock stranded advisory lock in pool; peer cannot take over")
	}
}
func TestPostgresLeaderDetectsTerminatedSessionAndRejoins(t *testing.T) {
	a, b := postgresFailureElectors(t)
	a.tick()
	if !a.IsLeader() {
		t.Fatal("initial election failed")
	}
	var pid int
	if err := a.conn.QueryRowContext(context.Background(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	var killed bool
	if err := b.db.QueryRow("SELECT pg_terminate_backend($1)", pid).Scan(&killed); err != nil || !killed {
		t.Fatal("terminate failed", err)
	}
	a.tick()
	if a.IsLeader() {
		t.Fatal("failed ping kept former authority")
	}
	b.tick()
	if !b.IsLeader() {
		t.Fatal("peer failed to take over")
	}
	a.tick()
	if a.IsLeader() {
		t.Fatal("former leader reacquired peer lock")
	}
	b.release()
	a.tick()
	if !a.IsLeader() {
		t.Fatal("former leader cannot recover")
	}
}
