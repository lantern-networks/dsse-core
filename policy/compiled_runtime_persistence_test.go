package policy

import (
	"bytes"
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
)

// Derived rules must never rewrite the authored runtime overlay. A CP can
// recompile with an older overlay after another CP has saved security controls.
func TestCompiledRulesDoNotWriteRuntimeAuthority(t *testing.T) {
	p := &incomingFaultStore{}
	stale, peer := NewStore(nil), NewStore(nil)
	for _, s := range []*Store{stale, peer} {
		if err := s.SetRuntimeStatePersister(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := peer.SetServerInitiatedEnabledConfirmed("peer", true); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), p.raw...)
	for _, rules := range [][]decision.EastWestRule{{{ID: "derived", Mode: "deny", Destinations: []string{"db.invalid"}}}, nil} {
		generation := stale.ConfigGeneration()
		stale.SetCompiledEastWestRules("local", rules)
		if !bytes.Equal(before, p.raw) {
			t.Fatal("recompilation overwrote peer runtime authority")
		}
		if stale.ConfigGeneration() <= generation {
			t.Fatal("derived generation did not advance")
		}
		if got := stale.EffectiveEastWestRules("local"); len(got) != len(rules) {
			t.Fatalf("derived rules not applied/cleared: %+v", got)
		}
	}
	restarted := NewStore(nil)
	if err := restarted.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	if !restarted.ServerInitiatedEnabledFor("peer") {
		t.Fatal("peer posture lost after restart")
	}
}
