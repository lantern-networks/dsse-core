package main

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// ★★★ A KEY ONLY ONE SIDE MODELS IS A KEY THE OTHER SIDE DROPS IN SILENCE (2026-08-19, reported from
// win-dev-1 after two rounds of investigation on the wrong side).
//
// The interception-root announcement was moved onto the per-minute policy document precisely because the trust
// bundle is gated behind a monotonic serial: an agent takes a new bundle only when the serial advances, so a
// deployment that is not rotating never sees a changed answer. The Edge duly wrote interception_root_sha256
// into the document — and agentpolicy.Payload, the type an agent parses it into, had no such field. On Windows
// the key landed nowhere. That box went on answering the readiness question from a bundle adopted fifteen days
// earlier, reporting wanted=1 found=1 for a root nothing had signed under for days.
//
// Nobody could see it from either end: the Edge's log says it sent the field, the agent's log says it holds
// what it was told to hold, and both are true. So the contract is asserted here — every key the Edge puts in
// the document must be modelled by the shared type. The failure names the key, because "the payload changed"
// is not actionable and "interception_root_sha256 is dropped by every struct-based reader" is.
func TestEveryKeyTheAgentPolicyCarriesIsModelledByTheSharedType(t *testing.T) {
	// The document as the Edge builds it. Kept as a literal rather than reaching into the route, because the
	// point is the WIRE: what an agent receives, and whether the shared type can hold it.
	sent := map[string]any{
		"schema_version":                   agentpolicy.EnvelopeType,
		"tenant_id":                        "tenant_reference_lab",
		"device_identity":                  "win-dev-1",
		"device_group":                     "engineering",
		"excluded_app_signing_ids":         []string{"com.anthropic.claude-code"},
		"renew_certificates_issued_before": "2026-08-19T00:00:00Z",
		"interception_root_sha256":         []string{"0ac681cd04f2d317c19e5b171650dc4cd92e6174a8a0d1e93f733a809432d5f3"},
	}

	raw, err := json.Marshal(sent)
	if err != nil {
		t.Fatal(err)
	}
	var parsed agentpolicy.Payload
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("an agent cannot parse the document this Edge sends: %v", err)
	}
	back, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]any
	if err := json.Unmarshal(back, &round); err != nil {
		t.Fatal(err)
	}

	dropped := []string{}
	for k := range sent {
		if _, ok := round[k]; !ok {
			dropped = append(dropped, k)
		}
	}
	sort.Strings(dropped)
	if len(dropped) > 0 {
		t.Fatalf("the Edge sends %s and agentpolicy.Payload has no field for %s — every agent that parses this "+
			"document into the shared type drops it, and neither side's log says so: the Edge reports sending "+
			"it and the agent reports holding what it was told", strings.Join(dropped, ", "), strings.Join(dropped, ", "))
	}

	// The control: a key can survive with its value emptied, which reads as "the device was told to look for
	// nothing" — the same outage wearing a quieter face. Asserted through the round-tripped MAP rather than
	// through a struct field, deliberately: referencing the field would make this file fail to COMPILE when the
	// field is missing, and a build error names the test rather than the class. The failure has to be a
	// sentence about a dropped key.
	got, _ := round["interception_root_sha256"].([]any)
	if len(got) != 1 || !strings.HasPrefix(got[0].(string), "0ac681cd") {
		t.Fatalf("the key survived and its value did not: %v", round["interception_root_sha256"])
	}
}
