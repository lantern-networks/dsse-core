package steerexclusion

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestFilePersistenceSurvivesRestart proves admin-set exclusions survive an Edge restart: a policy Upserted
// through one file-backed Persistence is returned by LoadAll on a FRESH instance pointed at the same file.
func TestFilePersistenceSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "steer_exclusions.json")
	now := time.Now()

	// First "process": create a store backed by a fresh file, add a policy.
	fp1 := NewFilePersistence(path)
	store1, err := NewStoreWithPersistence(fp1)
	if err != nil {
		t.Fatalf("NewStoreWithPersistence (first): %v", err)
	}
	saved, err := store1.Upsert(Policy{
		TenantID:              "t1",
		ScopeType:             scopeTenant,
		ExcludedAppSigningIDs: []string{"com.example.app"},
		Note:                  "keep across restart",
	}, now)
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Second "process": a brand-new persistence + store over the SAME file must see the policy.
	fp2 := NewFilePersistence(path)
	store2, err := NewStoreWithPersistence(fp2)
	if err != nil {
		t.Fatalf("NewStoreWithPersistence (restart): %v", err)
	}
	got, ok := store2.Get(saved.ID, "t1")
	if !ok {
		t.Fatalf("policy %s not found after restart", saved.ID)
	}
	if len(got.ExcludedAppSigningIDs) != 1 || got.ExcludedAppSigningIDs[0] != "com.example.app" {
		t.Fatalf("restored policy has wrong signing ids: %+v", got.ExcludedAppSigningIDs)
	}
}

// TestFilePersistenceDeletePersists proves a Delete is durable: after deleting through one store, a fresh
// store over the same file no longer sees the policy.
func TestFilePersistenceDeletePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "steer_exclusions.json")
	now := time.Now()

	fp1 := NewFilePersistence(path)
	store1, err := NewStoreWithPersistence(fp1)
	if err != nil {
		t.Fatalf("NewStoreWithPersistence (first): %v", err)
	}
	saved, err := store1.Upsert(Policy{
		TenantID:              "t1",
		ScopeType:             scopeDevice,
		ScopeID:               "device-42",
		ExcludedAppSigningIDs: []string{"com.example.app"},
	}, now)
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if !store1.Delete(saved.ID, "t1", now) {
		t.Fatalf("Delete returned false for %s", saved.ID)
	}

	fp2 := NewFilePersistence(path)
	store2, err := NewStoreWithPersistence(fp2)
	if err != nil {
		t.Fatalf("NewStoreWithPersistence (restart): %v", err)
	}
	if _, ok := store2.Get(saved.ID, "t1"); ok {
		t.Fatalf("policy %s still present after persisted delete", saved.ID)
	}
}

// A failed save reaches both the caller and the monitoring hook.
func TestFilePersistenceSaveFailureSurfacesViaOnPersistError(t *testing.T) {
	// A path under a directory that does not exist makes FilePersister.Save fail (the temp write cannot be
	// created), while LoadAll on the same missing file is a clean empty start.
	path := filepath.Join(t.TempDir(), "does-not-exist-dir", "steer_exclusions.json")

	prev := OnPersistError
	defer func() { OnPersistError = prev }()
	var gotErr error
	OnPersistError = func(err error) { gotErr = err }

	fp := NewFilePersistence(path)
	if _, err := fp.LoadAll(context.Background()); err != nil {
		t.Fatalf("LoadAll on missing file should be a clean empty start, got: %v", err)
	}
	// Neither the operation nor its backend cache may claim success.
	if err := fp.Upsert(context.Background(), &Policy{ID: "sx_1", TenantID: "t1"}); err == nil {
		t.Fatal("Upsert must return the save error")
	}
	if len(fp.byID) != 0 {
		t.Fatal("failed save changed backend cache")
	}
	if gotErr == nil {
		t.Fatalf("expected save failure to surface via OnPersistError, got nil")
	}
}
