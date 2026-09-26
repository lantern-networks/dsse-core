package policy

import (
	"bytes"
	"errors"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/decision"
)

func TestEastWestAdminUpdateWaitsForOneConfirmedSave(t *testing.T) {
	p := &incomingFaultStore{}
	s := NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	enabled, partial := true, true
	ttl := 60
	rules := []decision.EastWestRule{{ID: "prior", Mode: "deny"}}
	if err := s.ApplyEastWestUpdateConfirmed("a", &rules, &ttl, &enabled, &partial); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyEastWestUpdateConfirmed("b", nil, nil, &enabled, &partial); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), p.raw...)
	gen := s.ConfigGeneration()
	full := false
	updated := []decision.EastWestRule{{ID: "new", Mode: "allow"}}
	newTTL := 120
	for _, failure := range []error{errors.New("storage refused"), errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)} {
		p.failure = failure
		if err := s.ApplyEastWestUpdateConfirmed("a", &updated, &newTTL, &enabled, &full); !errors.Is(err, ErrPolicyPersistence) {
			t.Fatal(err)
		}
		if !s.EastWestAllowsUnmatched("a") || !s.EastWestAllowsUnmatched("b") || s.EastWestMaxGrantTTL("a") != 60 || s.EastWestRulesFor("a")[0].ID != "prior" || s.ConfigGeneration() != gen || !bytes.Equal(p.raw, before) {
			t.Fatal("rejected candidate published")
		}
	}
	p.failure = nil
	if err := s.ApplyEastWestUpdateConfirmed("a", &updated, &newTTL, &enabled, &full); err != nil {
		t.Fatal(err)
	}
	reloaded := NewStore(nil)
	if err := reloaded.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	if reloaded.EastWestAllowsUnmatched("a") || !reloaded.EastWestIsEnabled("a") || !reloaded.EastWestAllowsUnmatched("b") || reloaded.EastWestMaxGrantTTL("a") != 120 || reloaded.EastWestRulesFor("a")[0].ID != "new" {
		t.Fatal("committed update did not survive reload")
	}
}
