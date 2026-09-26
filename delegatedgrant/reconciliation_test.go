package delegatedgrant

import (
	"errors"
	"github.com/lantern-networks/dsse-core/model"
	"testing"
	"time"
)

type rejectSave struct{}

func (rejectSave) Load() ([]byte, error) { return nil, nil }
func (rejectSave) Save([]byte) error     { return errors.New("storage unavailable") }
func TestReconciliationSaveMustBeConfirmed(t *testing.T) {
	s := NewStore(0)
	s.SetPersister(rejectSave{})
	if _, err := s.Upsert(model.DelegatedAccessGrant{ID: "new", TenantID: "own", Status: "active"}); err == nil {
		t.Fatal("failed save returned success")
	}
}
func TestReconciliationRevocationAdvancesDistribution(t *testing.T) {
	s := NewStore(0)
	s.Upsert(model.DelegatedAccessGrant{ID: "grant", TenantID: "own", Status: "active"})
	gen := s.ConfigGeneration()
	if _, err := s.Revoke("grant", "requested", time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.ConfigGeneration() <= gen {
		t.Fatal("revocation did not advance distribution")
	}
}
func TestReconciliationSameIDKeepsBothOrganizations(t *testing.T) {
	s := NewStore(0)
	for _, tenant := range []string{"first", "second"} {
		if _, err := s.Upsert(model.DelegatedAccessGrant{ID: "same", TenantID: tenant, Status: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	if s.Count() != 2 {
		t.Fatal("same ID overwrote another organization")
	}
}
