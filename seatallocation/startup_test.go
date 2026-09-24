package seatallocation

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type unreadableAllocationStore struct{ writes int }

func (p *unreadableAllocationStore) Load() ([]byte, error) {
	return nil, errors.New("storage unavailable")
}
func (p *unreadableAllocationStore) Save([]byte) error { p.writes++; return nil }

func TestStartupLoadFailurePreservesStateAndPersister(t *testing.T) {
	good := &allocationFaultStore{}
	s := NewStore()
	if err := s.SetPersister(good); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Allocate(Policy{PoolSeats: 20}, "customer", 5, "operator", "", "now"); err != nil {
		t.Fatal(err)
	}
	gen := s.Generation()
	bad := &unreadableAllocationStore{}
	if err := s.SetPersister(bad); err == nil {
		t.Fatal("load error ignored")
	}
	if s.SeatsFor("customer") != 5 || s.Generation() != gen {
		t.Fatal("load failure changed state")
	}
	if _, err := s.Allocate(Policy{PoolSeats: 20}, "customer", 7, "operator", "", "later"); err != nil {
		t.Fatal(err)
	}
	restored := NewStore()
	if err := restored.SetPersister(good); err != nil {
		t.Fatal(err)
	}
	if restored.SeatsFor("customer") != 7 || bad.writes != 0 {
		t.Fatal("failed load replaced working persistence")
	}
}
func TestStartupRejectsUnknownSnapshotWithoutOverwriting(t *testing.T) {
	for _, raw := range []string{"", "null", "{}", `{"schema_version":"future","allocations":{}}`, `{"schema_version":"dsse.seat_allocations.v1","allocations":null}`, `{"schema_version":"dsse.seat_allocations.v1","allocations":{"a":{"tenant_id":"b","seats":1}}}`, `{"schema_version":"dsse.seat_allocations.v1","allocations":{"a":{"tenant_id":"a","seats":-1}}}`, `{"allocations":`} {
		t.Run(raw, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "seats.json")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			if err := NewStore().SetStateFile(path); err == nil {
				t.Fatal("unknown state accepted")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != raw {
				t.Fatal("snapshot changed", err)
			}
		})
	}
}
func TestStartupFirstBootAndSavedEmptySnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seats.json")
	s := NewStore()
	if err := s.SetStateFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Allocate(Policy{PoolSeats: 10}, "Customer", 5, "operator", "", "now"); err != nil {
		t.Fatal(err)
	}
	restored := NewStore()
	if err := restored.SetStateFile(path); err != nil {
		t.Fatal(err)
	}
	if restored.SeatsFor("customer") != 5 {
		t.Fatal("saved seats lost")
	}
	if _, err := restored.RemoveConfirmed("customer"); err != nil {
		t.Fatal(err)
	}
	empty := NewStore()
	if err := empty.SetStateFile(path); err != nil || len(empty.List()) != 0 {
		t.Fatal("valid empty state refused", err)
	}
}
