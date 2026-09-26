package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
)

type eastWestFaultPersisterPublicBaseline struct {
	raw     []byte
	failure error
	saves   int
}

func (p *eastWestFaultPersisterPublicBaseline) Load() ([]byte, error) {
	return append([]byte(nil), p.raw...), nil
}
func (p *eastWestFaultPersisterPublicBaseline) Save(raw []byte) error {
	p.saves++
	if p.failure != nil {
		return p.failure
	}
	p.raw = append([]byte(nil), raw...)
	return nil
}

func TestEastWestEditPublishesOnlyAfterConfirmedSavePublicBaseline(t *testing.T) {
	p := &eastWestFaultPersisterPublicBaseline{}
	s := NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	partial, enabled, full := true, true, false
	initial := []decision.EastWestRule{{ID: "old", Mode: "deny"}}
	ttl := 60
	if err := s.ApplyEastWestUpdateConfirmed("tenant", &initial, &ttl, &enabled, &partial); err != nil {
		t.Fatal(err)
	}
	prior := append([]byte(nil), p.raw...)
	gen := s.ConfigGeneration()
	updated := []decision.EastWestRule{{ID: "new", Mode: "allow"}}
	newTTL := 120
	p.failure = errors.New("storage refused")
	if err := s.ApplyEastWestUpdateConfirmed("tenant", &updated, &newTTL, &enabled, &full); !errors.Is(err, ErrPolicyPersistence) {
		t.Fatalf("save error = %v", err)
	}
	if !bytes.Equal(prior, p.raw) || s.ConfigGeneration() != gen || !s.EastWestAllowsUnmatched("tenant") || s.EastWestMaxGrantTTL("tenant") != ttl || s.EastWestRulesFor("tenant")[0].ID != "old" {
		t.Fatal("rejected candidate was published")
	}
	p.failure = nil
	if err := s.ApplyEastWestUpdateConfirmed("tenant", &updated, &newTTL, &enabled, &full); err != nil {
		t.Fatal(err)
	}
	if p.saves != 3 {
		t.Fatalf("saves = %d, want one per edit", p.saves)
	}
	reloaded := NewStore(nil)
	if err := reloaded.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	if reloaded.EastWestAllowsUnmatched("tenant") || reloaded.EastWestMaxGrantTTL("tenant") != 120 || reloaded.EastWestRulesFor("tenant")[0].ID != "new" {
		t.Fatal("confirmed update did not survive reload")
	}
}

type eastWestSharedPersisterPublicBaseline struct{ raw []byte }

func (p *eastWestSharedPersisterPublicBaseline) Load() ([]byte, error) {
	return append([]byte(nil), p.raw...), nil
}
func (p *eastWestSharedPersisterPublicBaseline) Save(raw []byte) error {
	p.raw = append([]byte(nil), raw...)
	return nil
}
func (p *eastWestSharedPersisterPublicBaseline) Update(edit func([]byte) ([]byte, error)) error {
	next, err := edit(p.raw)
	if err == nil {
		p.raw = append([]byte(nil), next...)
	}
	return err
}

func TestEastWestEditKeepsOtherCPSectionsPublicBaseline(t *testing.T) {
	p := &eastWestSharedPersisterPublicBaseline{raw: []byte(`{"schema_version":"admin_policy_runtime_state.v1","server_initiated_enabled":{"peer":true},"future_section":{"keep":"yes"}}`)}
	s := NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	mode := true
	if err := s.ApplyEastWestUpdateConfirmed("tenant", nil, nil, &mode, nil); err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(p.raw, &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc["server_initiated_enabled"]) != `{"peer":true}` || string(doc["future_section"]) != `{"keep":"yes"}` {
		t.Fatalf("unrelated sections changed: %s", p.raw)
	}
}

func TestEastWestEditRejectsDisappearedAuthorityPublicBaseline(t *testing.T) {
	p := &eastWestSharedPersisterPublicBaseline{raw: []byte(`{"schema_version":"admin_policy_runtime_state.v1","east_west_enabled":{"tenant":true}}`)}
	s := NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	gen := s.ConfigGeneration()
	p.raw = nil
	off := false
	if err := s.ApplyEastWestUpdateConfirmed("tenant", nil, nil, &off, nil); !errors.Is(err, ErrPolicyPersistence) {
		t.Fatalf("lost authority error = %v", err)
	}
	if !s.EastWestIsEnabled("tenant") || s.ConfigGeneration() != gen || p.raw != nil {
		t.Fatal("lost authority was replaced by a fresh default")
	}
}
