package agentupdate

import (
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// ★★ AN ENVELOPE THAT IS ONLY A TYPE IS NOT AN ENVELOPE (2026-08-14, thirty-first review, PLAUSIBLE #3). The
// review suspected the two platforms disagreed about how much of an envelope must be present — macOS demanding
// five fields, Windows accepting the type alone, so a half-written document would freeze one platform and be
// refused by the other. Both readers in fact hand the same struct to this one function, so the contract is
// here, and this pins it: a document carrying the right type and nothing else is REFUSED, on both.
func TestATypeAloneIsRefused(t *testing.T) {
	now := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)
	_, err := Open(agentpolicy.Envelope{Type: EnvelopeType}, []string{
		"fb2dc668ad6191ffec99849556a194a771e4fcc415ac8dd38b6524d748d251ba",
	}, now)
	if err == nil {
		t.Fatal("an envelope with a correct type and no payload, no signature and no key id was ACCEPTED — a " +
			"half-written courier file would be treated as a manifest")
	}
	if strings.Contains(strings.ToLower(err.Error()), "type") {
		t.Logf("refused on the type check as expected: %v", err)
	}
}

// And the type itself is still checked, so a correctly-formed envelope of the WRONG kind cannot be read as a
// manifest — the rollout plan is signed by a different key for exactly this reason.
func TestAWrongTypeIsRefused(t *testing.T) {
	now := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)
	if _, err := Open(agentpolicy.Envelope{Type: RolloutPlanEnvelopeType}, []string{
		"fb2dc668ad6191ffec99849556a194a771e4fcc415ac8dd38b6524d748d251ba",
	}, now); err == nil {
		t.Fatal("a rollout-plan envelope was opened as an update manifest")
	}
}
