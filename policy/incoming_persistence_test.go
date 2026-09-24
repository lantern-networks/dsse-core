package policy

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"reflect"
	"testing"
)

type incomingFaultStore struct {
	raw     []byte
	failure error
}

func (p *incomingFaultStore) Load() ([]byte, error) { return p.raw, nil }
func (p *incomingFaultStore) Save(raw []byte) error {
	if p.failure != nil {
		return p.failure
	}
	p.raw = append([]byte(nil), raw...)
	return nil
}
func TestIncomingChangesWaitForStorage(t *testing.T) {
	p := &incomingFaultStore{}
	s := NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	ex := model.LegacyException{ID: "same", TenantID: "a", SourceServer: "10.0.0.1", Port: 443}
	if err := s.UpsertLegacyExceptionConfirmed("a", ex); err != nil {
		t.Fatal(err)
	}
	foreign := ex
	foreign.TenantID = "b"
	foreign.Port = 22
	if err := s.UpsertLegacyExceptionConfirmed("b", foreign); err != nil {
		t.Fatal(err)
	}
	for _, failure := range []error{errors.New("private disk detail"), errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)} {
		p.failure = failure
		before := append([]byte(nil), p.raw...)
		gen := s.ConfigGeneration()
		if err := s.SetServerInitiatedEnabledConfirmed("a", true); !errors.Is(err, ErrPolicyPersistence) {
			t.Fatal(err)
		}
		update := ex
		update.Port = 8443
		if err := s.UpsertLegacyExceptionConfirmed("a", update); !errors.Is(err, ErrPolicyPersistence) {
			t.Fatal(err)
		}
		if removed, err := s.RemoveLegacyExceptionConfirmed("a", "same"); removed || !errors.Is(err, ErrPolicyPersistence) {
			t.Fatalf("%v %v", removed, err)
		}
		if s.ServerInitiatedEnabledFor("a") || s.ConfigGeneration() != gen || !reflect.DeepEqual(s.LegacyExceptionsFor("a"), []model.LegacyException{ex}) || !reflect.DeepEqual(s.LegacyExceptionsFor("b"), []model.LegacyException{foreign}) || !reflect.DeepEqual(p.raw, before) {
			t.Fatal("rejected save published or mutated storage")
		}
	}
	p.failure = nil
	if err := s.SetServerInitiatedEnabledConfirmed("a", true); err != nil {
		t.Fatal(err)
	}
	if removed, err := s.RemoveLegacyExceptionConfirmed("a", "same"); !removed || err != nil {
		t.Fatalf("%v %v", removed, err)
	}
	restored := NewStore(nil)
	if err := restored.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	if !restored.ServerInitiatedEnabledFor("a") || len(restored.LegacyExceptionsFor("a")) != 0 || len(restored.LegacyExceptionsFor("b")) != 1 {
		t.Fatal("retry not durable or foreign changed")
	}
}
