package seatallocation

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestCaseDistinctTenantAllocationsSurvivePersistenceAndErasure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seats.json")
	s := NewStore()
	if err := s.SetStateFile(path); err != nil {
		t.Fatal(err)
	}
	for tenant, seats := range map[string]int{"Acme": 7, "acme": 11} {
		if _, err := s.Allocate(Policy{PoolSeats: 20}, tenant, seats, "operator", "", "now"); err != nil {
			t.Fatal(err)
		}
	}
	if s.SeatsFor("Acme") != 7 || s.SeatsFor("acme") != 11 || s.Allocated() != 18 || len(s.List()) != 2 {
		t.Fatalf("case-distinct allocations collapsed: %#v", s.List())
	}
	if _, err := s.Allocate(Policy{PoolSeats: 20}, "Acme", 10, "operator", "", "now"); !errors.Is(err, ErrPoolExceeded) {
		t.Fatalf("other tenant's seats were not counted: %v", err)
	}
	reloaded := NewStore()
	if err := reloaded.SetStateFile(path); err != nil {
		t.Fatal(err)
	}
	if reloaded.SeatsFor("Acme") != 7 || reloaded.SeatsFor("acme") != 11 {
		t.Fatal("restart changed tenant allocation ownership")
	}
	if n, err := reloaded.RemoveTenant(" Acme "); err != nil || n != 1 {
		t.Fatalf("remove exact tenant: %d %v", n, err)
	}
	if reloaded.Has("Acme") || !reloaded.Has("acme") || reloaded.CountForTenant("acme") != 1 || reloaded.SeatsFor("acme") != 11 {
		t.Fatal("removing one tenant erased the other allocation")
	}
}
