package delegatedgrant

import (
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/model"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func capacityRecord(tenant, id string, now time.Time) model.DelegatedAccessGrant {
	return model.DelegatedAccessGrant{ID: id, TenantID: tenant, ActorNHIID: "agent", SubjectUserID: "person", Status: "active", ToolIDs: []string{"read_repo"}, CreatedAt: stringPtr(now.Format(time.RFC3339)), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
}
func TestCapacityRetainsTerminalAuthorizationAcrossRestarts(t *testing.T) {
	for _, terminal := range []string{"expired", "revoked"} {
		t.Run(terminal, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "records.json")
			now := time.Now().UTC()
			s := NewStore(1)
			if err := s.SetStatePath(path); err != nil {
				t.Fatal(err)
			}
			original := capacityRecord("a", "retained", now)
			if _, err := s.Upsert(original); err != nil {
				t.Fatal(err)
			}
			if !IsActive(original, now) {
				t.Fatal("fixture is not initially active")
			}
			if terminal == "revoked" {
				_, err := s.RevokeForTenant("a", "retained", "test", now)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				next := original
				next.Status = terminal
				if _, err := s.Upsert(next); err != nil {
					t.Fatal(err)
				}
			}
			for cycle := 0; cycle < 3; cycle++ {
				if cycle > 0 {
					s = NewStore(1)
					if err := s.SetStatePath(path); err != nil {
						t.Fatal(err)
					}
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				for _, tenant := range []string{"a", "other"} {
					if _, err := s.Upsert(capacityRecord(tenant, "pressure", now)); !errors.Is(err, ErrCapacity) {
						t.Fatalf("capacity refusal: %v", err)
					}
				}
				// A fresh future expiry must not resurrect an explicitly terminal outcome, even after its old window.
				for _, replayTime := range []time.Time{now, now.Add(2 * time.Hour)} {
					if _, err := s.Upsert(capacityRecord("a", "retained", replayTime)); err == nil || errors.Is(err, ErrCapacity) {
						t.Fatalf("terminal transition was not checked: %v", err)
					}
				}
				stored, ok := s.GetForTenant("a", "retained")
				if !ok || stored.Status != terminal || IsActive(stored, now) || s.Count() != 1 {
					t.Fatalf("terminal record lost: %+v", stored)
				}
				after, err := os.ReadFile(path)
				if err != nil || string(before) != string(after) {
					t.Fatal("refused admission/replay changed disk")
				}
			}
		})
	}
}
func TestCapacityLoweringPreservesLoadedRecordsAndExistingMutations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.json")
	now := time.Now().UTC()
	s := NewStore(3)
	if err := s.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"retained", "second", "third"} {
		if _, err := s.Upsert(capacityRecord("a", id, now)); err != nil {
			t.Fatal(err)
		}
	}
	s = NewStore(1)
	if err := s.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if s.Count() != 3 {
		t.Fatal("lowered capacity discarded saved records")
	}
	if _, err := s.Upsert(capacityRecord("a", "new", now)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("admission: %v", err)
	}
	if _, err := s.Upsert(capacityRecord("a", "second", now)); err != nil {
		t.Fatal(err)
	}
	_, err := s.RevokeForTenant("a", "retained", "test", now)
	if err != nil {
		t.Fatal(err)
	}
	raised := NewStore(4)
	if err := raised.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if _, err := raised.Upsert(capacityRecord("a", "new", now)); err != nil {
		t.Fatal(err)
	}
	saved, ok := raised.GetForTenant("a", "retained")
	if !ok || saved.Status != "revoked" || raised.Count() != 4 {
		t.Fatal("capacity increase lost revocation")
	}
}
func TestCapacityAdmissionIsAtomicUnderConcurrentCreates(t *testing.T) {
	s := NewStore(3)
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Upsert(capacityRecord("a", fmt.Sprint(i), time.Now()))
			if err == nil {
				admitted.Add(1)
			} else if !errors.Is(err, ErrCapacity) {
				t.Errorf("admission: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if s.Count() != 3 || admitted.Load() != 3 {
		t.Fatalf("count=%d admitted=%d", s.Count(), admitted.Load())
	}
}
