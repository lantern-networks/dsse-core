package appcatalog

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// TestDeleteAuthoredScopeAndSeed proves Delete is tenant-scoped, removes operator-authored entries (and persists
// the removal across a "restart"), is idempotent at the resource level, refuses to delete config-seed entries,
// and never crosses tenants.
func TestDeleteAuthoredScopeAndSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apps.json")
	ctx := context.Background()
	now := time.Now().UTC()

	store := NewStore()
	// Seed an entry BEFORE SetStatePath so it is recorded as the non-deletable config seed.
	if _, err := store.Upsert(ctx, Entry{ApplicationID: "seed1", TenantID: "t1", Name: "Seed"}, "t1", now); err != nil {
		t.Fatalf("seed upsert: %v", err)
	}
	if err := store.SetStatePath(path); err != nil {
		t.Fatalf("SetStatePath: %v", err)
	}
	// Author entries under two tenants.
	if _, err := store.Upsert(ctx, Entry{ApplicationID: "authored1", TenantID: "t1", Name: "Authored"}, "t1", now); err != nil {
		t.Fatalf("upsert t1: %v", err)
	}
	if _, err := store.Upsert(ctx, Entry{ApplicationID: "authored1", TenantID: "t2", Name: "Authored T2"}, "t2", now); err != nil {
		t.Fatalf("upsert t2: %v", err)
	}

	// Config-seed entry is not deletable.
	if err := store.Delete(ctx, "t1", "seed1"); !errors.Is(err, ErrApplicationNotDeletable) {
		t.Fatalf("delete seed err = %v, want ErrApplicationNotDeletable", err)
	}
	if _, ok, _ := store.Get(ctx, "t1", "seed1"); !ok {
		t.Fatal("config-seed entry must survive a delete attempt")
	}

	// Unknown id => not found.
	if err := store.Delete(ctx, "t1", "missing"); !errors.Is(err, ErrApplicationNotFound) {
		t.Fatalf("delete missing err = %v, want ErrApplicationNotFound", err)
	}

	// Delete the authored t1 entry; the t2 entry with the SAME id is untouched (tenant scope).
	if err := store.Delete(ctx, "t1", "authored1"); err != nil {
		t.Fatalf("delete authored t1: %v", err)
	}
	if _, ok, _ := store.Get(ctx, "t1", "authored1"); ok {
		t.Fatal("authored t1 entry should be gone")
	}
	if _, ok, _ := store.Get(ctx, "t2", "authored1"); !ok {
		t.Fatal("cross-tenant delete: t2 entry must remain")
	}

	// Idempotent at the resource level: deleting again is a deterministic not-found, end state unchanged.
	if err := store.Delete(ctx, "t1", "authored1"); !errors.Is(err, ErrApplicationNotFound) {
		t.Fatalf("second delete err = %v, want ErrApplicationNotFound", err)
	}

	// The removal is durable: a fresh store over the same file (re-seeded) does not resurrect authored1, but the
	// re-derived seed entry returns.
	restarted := NewStore()
	if _, err := restarted.Upsert(ctx, Entry{ApplicationID: "seed1", TenantID: "t1", Name: "Seed"}, "t1", now); err != nil {
		t.Fatalf("reseed: %v", err)
	}
	if err := restarted.SetStatePath(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok, _ := restarted.Get(ctx, "t1", "authored1"); ok {
		t.Fatal("deleted authored entry must not survive restart")
	}
	if _, ok, _ := restarted.Get(ctx, "t1", "seed1"); !ok {
		t.Fatal("re-seeded config entry must be present after restart")
	}
	if _, ok, _ := restarted.Get(ctx, "t2", "authored1"); !ok {
		t.Fatal("t2 authored entry must survive restart")
	}
}

// TestApplicationsPersistAndMergeOverSeed proves operator-authored applications survive a restart and that
// the persisted set is MERGED on top of the config seed (seeded apps stay, authored apps return).
func TestApplicationsPersistAndMergeOverSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apps.json")
	ctx := context.Background()
	now := time.Now().UTC()

	s1 := NewStore()
	if err := s1.SetStatePath(path); err != nil {
		t.Fatalf("SetStatePath: %v", err)
	}
	if _, err := s1.Upsert(ctx, Entry{ApplicationID: "authored1", TenantID: "t1", Name: "Authored"}, "t1", now); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Restart: a fresh store is first SEEDED (as cmd/edge does from route profiles), THEN loads the file.
	s2 := NewStore()
	if _, err := s2.Upsert(ctx, Entry{ApplicationID: "seed1", TenantID: "t1", Name: "Seed"}, "t1", now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s2.SetStatePath(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok, _ := s2.Get(ctx, "t1", "authored1"); !ok {
		t.Fatal("authored application did not survive restart")
	}
	if _, ok, _ := s2.Get(ctx, "t1", "seed1"); !ok {
		t.Fatal("config-seeded application was lost when merging the persisted set")
	}
}
