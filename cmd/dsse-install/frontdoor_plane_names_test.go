package main

import "testing"

// ★ THE MISTAKE THIS GUARDS IS THE NATURAL ONE. "agents.<domain>" is the door an operator thinks of first, so
// it is what they hand to -host — and prefixing it again produced agents.agents.<domain> in the certificate,
// in the front door's SNI rules, and in the address handed to connectors. Three things agreeing with each
// other and with nothing a client ever asks for.
func TestPlaneNamesAreNotPrefixedTwice(t *testing.T) {
	for _, tc := range []struct{ host, wantAgents, wantRecovery string }{
		{"example.test", "agents.example.test", "recovery.example.test"},
		{"agents.example.test", "agents.example.test", "recovery.example.test"},
		{"localhost", "agents.localhost", "recovery.localhost"},
		{"agents.localhost", "agents.localhost", "recovery.localhost"},
	} {
		got := planeNamesFor(tc.host)
		if got.Agents != tc.wantAgents || got.Recovery != tc.wantRecovery {
			t.Fatalf("planeNamesFor(%q) = agents:%q recovery:%q, want %q / %q",
				tc.host, got.Agents, got.Recovery, tc.wantAgents, tc.wantRecovery)
		}
		if !got.Split {
			t.Fatalf("planeNamesFor(%q) reported no split, so the planes would share one name", tc.host)
		}
	}
	// An address still cannot be prefixed, and the guard must not have changed that.
	if p := planeNamesFor("10.0.0.5"); p.Split || p.Agents != "10.0.0.5" {
		t.Fatalf("an address was turned into a name: %+v", p)
	}
}
