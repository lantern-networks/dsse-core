package edgeplane

import (
	"testing"
	"time"
)

// THE property the whole thing exists for: two Edges holding the same secret must derive the SAME key, with no
// coordination between them. Otherwise a client the load balancer moves pays a full handshake every time.
func TestFleetSessionTicketKeysAreIdenticalAcrossNodes(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	edgeA, okA := fleetSessionTicketKeys("fleet-secret", now)
	// A different wall clock on the second node, same rotation window — nodes are never perfectly in sync.
	edgeB, okB := fleetSessionTicketKeys("fleet-secret", now.Add(37*time.Minute))
	if !okA || !okB {
		t.Fatal("a configured secret must produce keys")
	}
	if edgeA[0] != edgeB[0] {
		t.Fatal("two Edges with the same secret derived DIFFERENT ticket keys — a client moved by the load " +
			"balancer would fail to resume and pay a full handshake, which is the entire problem this solves")
	}

	// A different secret must not collide, or one tenant/fleet could resume against another's node.
	other, _ := fleetSessionTicketKeys("different-secret", now)
	if other[0] == edgeA[0] {
		t.Fatal("different secrets produced the same key")
	}
}

// No secret => no fleet key. Deriving from an empty secret would give every deployment in existence the same
// predictable ticket key, which is far worse than losing cross-node resumption.
func TestFleetSessionTicketKeysRefuseEmptySecret(t *testing.T) {
	for _, s := range []string{"", "   ", "\t\n"} {
		if _, ok := fleetSessionTicketKeys(s, time.Now()); ok {
			t.Fatalf("an empty secret (%q) must NOT yield a key — a predictable fleet-wide ticket key is worse "+
				"than no resumption", s)
		}
	}
}

// Rotation happens, and the PREVIOUS key is retained. Without the overlap, every rollover would invalidate
// every outstanding ticket at once and cause the fleet-wide handshake storm this is meant to prevent.
func TestFleetSessionTicketKeysRotateWithOverlap(t *testing.T) {
	base := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	before, _ := fleetSessionTicketKeys("fleet-secret", base)
	after, _ := fleetSessionTicketKeys("fleet-secret", base.Add(sessionTicketRotationPeriod))

	if before[0] == after[0] {
		t.Fatal("the key did not rotate — a ticket key that never changes undermines forward secrecy, because " +
			"anyone who later obtains it can decrypt every session that resumed under it")
	}
	if len(after) < 2 {
		t.Fatal("after rotation both the current and previous keys must be installed")
	}
	if after[1] != before[0] {
		t.Fatal("the previous epoch's key was not retained — tickets issued just before the rollover would " +
			"stop resuming, causing exactly the handshake storm this avoids")
	}
	// Go issues new tickets with keys[0], so the current epoch has to come first.
	if after[0] == before[0] {
		t.Fatal("the current key must be first so new tickets use it")
	}
}

// Derivation is deterministic: same inputs, same output, every time. A node restart must not invalidate the
// fleet's outstanding tickets.
func TestFleetSessionTicketKeyDerivationIsStable(t *testing.T) {
	now := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	first, _ := fleetSessionTicketKeys("fleet-secret", now)
	second, _ := fleetSessionTicketKeys("fleet-secret", now)
	if first[0] != second[0] || first[1] != second[1] {
		t.Fatal("derivation is not deterministic; a restart would invalidate outstanding tickets")
	}
}
