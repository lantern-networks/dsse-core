package seatallocation

import (
	"errors"
	"path/filepath"
	"testing"
)

const now = "2026-10-01T00:00:00Z"

func strictPool(seats int) Policy { return Policy{PoolSeats: seats} }

func TestAllocationsAreBoundedByThePool(t *testing.T) {
	s := NewStore()
	if _, err := s.Allocate(strictPool(1000), "tenant_a", 600, "adm_alice", "", now); err != nil {
		t.Fatalf("within the pool: %v", err)
	}
	if _, err := s.Allocate(strictPool(1000), "tenant_b", 400, "adm_alice", "", now); err != nil {
		t.Fatalf("exactly filling the pool must be allowed: %v", err)
	}
	if _, err := s.Allocate(strictPool(1000), "tenant_c", 1, "adm_alice", "", now); !errors.Is(err, ErrPoolExceeded) {
		t.Fatalf("one seat past the pool must be refused, got %v", err)
	}
	if s.Allocated() != 1000 || s.Unallocated(1000) != 0 {
		t.Fatalf("allocated %d, unallocated %d", s.Allocated(), s.Unallocated(1000))
	}
}

// Re-allocating a tenant must count against its OWN previous figure, not on top of it. Getting this wrong makes
// the pool appear to fill up as an operator adjusts one tenant repeatedly.
func TestChangingATenantsAllocationReplacesIt(t *testing.T) {
	s := NewStore()
	if _, err := s.Allocate(strictPool(1000), "tenant_a", 900, "adm_alice", "", now); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := s.Allocate(strictPool(1000), "tenant_a", 950, "adm_alice", "", now); err != nil {
		t.Fatalf("raising one tenant within the pool must count against its own previous figure: %v", err)
	}
	if s.Allocated() != 950 {
		t.Fatalf("allocated %d, want 950", s.Allocated())
	}
	if _, err := s.Allocate(strictPool(1000), "tenant_a", 1001, "adm_alice", "", now); !errors.Is(err, ErrPoolExceeded) {
		t.Fatalf("past the pool is still refused, got %v", err)
	}
}

// The refusal belongs with the party who knows what they promised. An MSSP that deliberately oversubscribes can,
// but has to say so.
func TestOversubscriptionIsOffByDefaultAndAvailableOnPurpose(t *testing.T) {
	s := NewStore()
	if _, err := s.Allocate(strictPool(100), "tenant_a", 150, "adm_alice", "", now); !errors.Is(err, ErrPoolExceeded) {
		t.Fatalf("default must refuse, got %v", err)
	}
	loose := Policy{PoolSeats: 100, AllowOversubscription: true}
	if _, err := s.Allocate(loose, "tenant_a", 150, "adm_alice", "", now); err != nil {
		t.Fatalf("with oversubscription allowed: %v", err)
	}
	if got := s.Unallocated(100); got != -50 {
		t.Fatalf("the shortfall must be visible as %d, got %d", -50, got)
	}
}

// An MSSP reclaiming seats is legitimate, and the consequence lands on new enrolments rather than on machines
// already running. Refusing the reduction would leave an MSSP unable to reorganise its own pool without first
// persuading a customer to decommission hardware.
func TestAnAllocationMayBeReducedBelowCurrentUse(t *testing.T) {
	s := NewStore()
	if _, err := s.Allocate(strictPool(1000), "tenant_a", 500, "adm_alice", "", now); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if _, err := s.Allocate(strictPool(1000), "tenant_a", 100, "adm_alice", "reclaimed for another customer", now); err != nil {
		t.Fatalf("reducing an allocation must be allowed: %v", err)
	}
	// 400 devices are running against an allocation of 100. They keep running; only growth stops.
	v := MayEnrol(s.SeatsFor("tenant_a"), 400)
	if v.Allowed {
		t.Fatalf("a tenant over its allocation must not enrol more")
	}
	if v.Reason == "" {
		t.Fatalf("an operator needs to be told why")
	}
}

func TestSeatsAreFreedByRemovingATenant(t *testing.T) {
	s := NewStore()
	s.Allocate(strictPool(1000), "tenant_a", 700, "adm_alice", "", now)
	if !s.Remove("TENANT_A") {
		t.Fatalf("removal must not be case-sensitive")
	}
	if s.Allocated() != 0 {
		t.Fatalf("removing a tenant returns its seats: allocated %d", s.Allocated())
	}
	if s.Remove("tenant_a") {
		t.Fatalf("removing what is not there is not a change")
	}
}

func TestMayEnrolCountsAgainstTheAllocation(t *testing.T) {
	if v := MayEnrol(10, 9); !v.Allowed {
		t.Fatalf("room for one more must be allowed")
	}
	if v := MayEnrol(10, 10); v.Allowed {
		t.Fatalf("a full allocation must refuse")
	}
	if v := MayEnrol(10, 11); v.Allowed {
		t.Fatalf("over the allocation must refuse")
	}
	// A tenant nobody allocated to is not silently drawing from the remainder — under an MSSP, taking on a
	// customer includes giving them seats, and the message says so rather than reading as a bug.
	v := MayEnrol(0, 0)
	if v.Allowed {
		t.Fatalf("no allocation means no enrolment")
	}
	if v.Reason == "" {
		t.Fatalf("the reason must name the missing step")
	}
}

func TestAllocationsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seat_allocations.json")
	first := NewStore()
	first.SetStateFile(path)
	first.Allocate(strictPool(1000), "tenant_a", 600, "adm_alice", "", now)
	first.Allocate(strictPool(1000), "tenant_b", 200, "adm_alice", "", now)

	reborn := NewStore()
	reborn.SetStateFile(path)
	if reborn.SeatsFor("tenant_a") != 600 || reborn.SeatsFor("tenant_b") != 200 {
		t.Fatalf("allocations must survive: %+v", reborn.List())
	}
	// Losing these would read as zero seats everywhere and stop enrolment across the whole fleet, so the pool
	// arithmetic has to come back intact too.
	if reborn.Allocated() != 800 {
		t.Fatalf("allocated %d after reload, want 800", reborn.Allocated())
	}
}

func TestListShowsWhereThePoolWent(t *testing.T) {
	s := NewStore()
	s.Allocate(strictPool(1000), "tenant_small", 50, "adm_alice", "", now)
	s.Allocate(strictPool(1000), "tenant_large", 700, "adm_alice", "", now)
	got := s.List()
	if len(got) != 2 || got[0].TenantID != "tenant_large" {
		t.Fatalf("largest first, got %+v", got)
	}
}

func TestAllocationRequiresATenantAndRefusesNegatives(t *testing.T) {
	s := NewStore()
	if _, err := s.Allocate(strictPool(100), "  ", 10, "adm_alice", "", now); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("want ErrNoTenant, got %v", err)
	}
	if _, err := s.Allocate(strictPool(100), "tenant_a", -1, "adm_alice", "", now); !errors.Is(err, ErrNegative) {
		t.Fatalf("want ErrNegative, got %v", err)
	}
}
