package seatallocation

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"testing"
)

type allocationFaultStore struct {
	raw  []byte
	fail bool
}

func (p *allocationFaultStore) Load() ([]byte, error) { return p.raw, nil }
func (p *allocationFaultStore) Save(raw []byte) error {
	if p.fail {
		return errors.New("private storage detail")
	}
	p.raw = append([]byte(nil), raw...)
	return nil
}
func TestManagementPersistenceFailureRetainsAllocationAndGeneration(t *testing.T) {
	p := &allocationFaultStore{}
	s := NewStore()
	s.SetPersister(p)
	policy := Policy{PoolSeats: 20}
	if _, err := s.Allocate(policy, "customer", 5, "operator", "", "now"); err != nil {
		t.Fatal(err)
	}
	generation := s.Generation()
	p.fail = true
	if _, err := s.Allocate(policy, "customer", 10, "operator", "", "later"); !errors.Is(err, ErrPersistence) {
		t.Fatal(err)
	}
	if removed, err := s.RemoveConfirmed("customer"); removed || !errors.Is(err, ErrPersistence) {
		t.Fatalf("%v %v", removed, err)
	}
	if s.SeatsFor("customer") != 5 || s.Generation() != generation {
		t.Fatal("failed save published candidate")
	}
	p.fail = false
	if _, err := s.Allocate(policy, "customer", 10, "operator", "", "later"); err != nil {
		t.Fatal(err)
	}
	restored := NewStore()
	restored.SetPersister(p)
	if restored.SeatsFor("customer") != 10 {
		t.Fatal("retry not durable")
	}
	if removed, err := s.RemoveConfirmed("customer"); !removed || err != nil {
		t.Fatalf("%v %v", removed, err)
	}
	restored = NewStore()
	restored.SetPersister(p)
	if len(restored.List()) != 0 {
		t.Fatal("removal not durable")
	}
}

type allocationSavedWarning struct{ allocationFaultStore }

func (p *allocationSavedWarning) Save(raw []byte) error {
	p.raw = append([]byte(nil), raw...)
	return blobstore.ErrSavedWithoutAtomicity
}
func TestConfirmedNonAtomicAllocationSaveRemainsAccepted(t *testing.T) {
	p := &allocationSavedWarning{}
	s := NewStore()
	s.SetPersister(p)
	if _, err := s.Allocate(Policy{PoolSeats: 20}, "customer", 5, "operator", "", "now"); err != nil {
		t.Fatal(err)
	}
	if s.SeatsFor("customer") != 5 {
		t.Fatal("confirmed save not adopted")
	}
}

func TestUnconfirmedFlushDoesNotPublishAllocation(t *testing.T) {
	p := &allocationFaultStore{}
	s := NewStore()
	s.SetPersister(p)
	if _, err := s.Allocate(Policy{PoolSeats: 20}, "customer", 5, "operator", "", "now"); err != nil {
		t.Fatal(err)
	}
	gen := s.Generation()
	s.SetPersister(unconfirmedAllocationSave{p})
	if _, err := s.Allocate(Policy{PoolSeats: 20}, "customer", 10, "operator", "", "later"); !errors.Is(err, ErrPersistence) {
		t.Fatalf("unconfirmed flush accepted: %v", err)
	}
	if s.SeatsFor("customer") != 5 || s.Generation() != gen {
		t.Fatal("unconfirmed save published")
	}
}

type unconfirmedAllocationSave struct{ *allocationFaultStore }

func (p unconfirmedAllocationSave) Save(raw []byte) error {
	p.raw = append([]byte(nil), raw...)
	return errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
}
