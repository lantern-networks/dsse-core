package policy

import (
	"encoding/json"
	"errors"
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
	for _, failure := range []error{errors.New("private disk detail"), errors.New("commit not confirmed")} {
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

func TestIncomingEditPreservesOtherCPAndUnknownSections(t *testing.T) {
	p := &eastWestSharedPersister{raw: []byte(`{"schema_version":"admin_policy_runtime_state.v1","future_section":{"keep":true}}`)}
	a, b := NewStore(nil), NewStore(nil)
	for _, s := range []*Store{a, b} {
		if err := s.SetRuntimeStatePersister(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.UpsertLegacyExceptionConfirmed("a", model.LegacyException{ID: "a", TenantID: "a", Port: 8443}); err != nil {
		t.Fatal(err)
	}
	enabled := true
	if err := b.ApplyEastWestUpdateConfirmed("b", nil, nil, &enabled, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.UpsertLegacyExceptionConfirmed("b", model.LegacyException{ID: "b", TenantID: "b", Port: 22}); err != nil {
		t.Fatal(err)
	}
	if err := a.SetServerInitiatedEnabledConfirmed("a", true); err != nil {
		t.Fatal(err)
	}
	if removed, err := a.RemoveLegacyExceptionConfirmed("a", "a"); !removed || err != nil {
		t.Fatalf("delete %v %v", removed, err)
	}
	fresh := NewStore(nil)
	if err := fresh.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	if !fresh.EastWestIsEnabled("b") || !fresh.ServerInitiatedEnabledFor("a") || len(fresh.LegacyExceptionsFor("a")) != 0 || len(fresh.LegacyExceptionsFor("b")) != 1 {
		t.Fatal("independent committed changes lost")
	}
	var document map[string]json.RawMessage
	json.Unmarshal(p.raw, &document)
	if string(document["future_section"]) != `{"keep":true}` {
		t.Fatal("unknown section lost")
	}
}
