package main

import (
	"path/filepath"

	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

func TestLegalHoldStoreSetIsHeldPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legal_hold.json")
	now := time.Now()
	s1 := newLegalHoldStore(blobstore.FilePersister{Path: path})
	if s1.IsHeld("t1") {
		t.Fatal("t1 should not be held initially")
	}
	s1.Set("t1", "admin@lab", "acme v doe", true, now)
	if !s1.IsHeld("t1") {
		t.Fatal("t1 should be held after Set(active)")
	}
	if got := s1.List(); len(got) != 1 || got[0].TenantID != "t1" || got[0].Reason != "acme v doe" {
		t.Fatalf("List = %+v", got)
	}
	// Persistence: a fresh store from the same path restores the hold (must survive a restart).
	s2 := newLegalHoldStore(blobstore.FilePersister{Path: path})
	if !s2.IsHeld("t1") {
		t.Fatal("hold must survive restart (reload)")
	}
	// Release.
	s2.Set("t1", "admin@lab", "", false, now)
	if s2.IsHeld("t1") {
		t.Fatal("t1 should be released after Set(inactive)")
	}
	if s3 := newLegalHoldStore(blobstore.FilePersister{Path: path}); s3.IsHeld("t1") {
		t.Fatal("release must persist")
	}
}

func TestLegalHoldNilSafe(t *testing.T) {
	var s *legalHoldStore
	if s.IsHeld("x") {
		t.Fatal("nil store must report not held")
	}
	s.Set("x", "", "", true, time.Now()) // must not panic
}
