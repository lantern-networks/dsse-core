package humanapproval

import (
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/model"
	"testing"
)

type failingPersister struct{}

func (failingPersister) Load() ([]byte, error) { return nil, nil }
func (failingPersister) Save([]byte) error     { return fmt.Errorf("disk full") }

// Creation is save-before-publication. Explicit revocation retains the denial and every retry must save.
func TestUpsertAndRevokeSurfacePersistFailure(t *testing.T) {
	s := NewStore(0)
	if e := s.SetPersister(failingPersister{}); e != nil {
		t.Fatal(e)
	}
	event := model.HumanApprovalEvent{ID: "h1", TenantID: "t1", ApprovalResult: "approved"}
	if _, e := s.Upsert(event); !errors.Is(e, ErrPersistence) {
		t.Fatal(e)
	}
	if _, ok := s.Get("h1"); ok {
		t.Fatal("failed approval became live")
	}
	if e := s.SetPersister(nil); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Upsert(event); e != nil {
		t.Fatal(e)
	}
	if e := s.SetPersister(failingPersister{}); e != nil {
		t.Fatal(e)
	}
	for attempt := 0; attempt < 2; attempt++ {
		revoked, ok, e := s.Revoke("h1", "compromised")
		if !ok || !errors.Is(e, ErrPersistence) || revoked.ApprovalResult != "revoked" {
			t.Fatalf("attempt %d: %+v %v %v", attempt, revoked, ok, e)
		}
	}
}
