package eastwest

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/policy"
)

// TestCompleteCeremonyRequiresProvenIdentity pins fail-open review finding #16: when the held flow CLAIMS a
// subject, the browser ceremony must have PROVEN that same subject. An empty authenticated identity (the ceremony
// proved no one) must NOT skip the check and issue the grant to the merely-claimed subject.
func TestCompleteCeremonyRequiresProvenIdentity(t *testing.T) {
	now := time.Now().UTC()
	mk := func() (*AuthChallengeStore, string) {
		ch := NewAuthChallengeStore()
		c := ch.Create(AuthChallenge{TenantID: "acme", SubjectUserID: "alice", DeviceID: "dev-1", Destination: "10.0.0.5", Protocol: "ssh"}, now)
		return ch, c.ID
	}
	store := policy.NewStore(nil)

	// Claimed subject "alice" but the ceremony proved NO identity (empty) -> must be rejected (was: issued to alice).
	ch, id := mk()
	if _, err := CompleteCeremony(store, ch, id, "", now); err == nil {
		t.Fatal("empty authenticated identity must NOT satisfy a claimed subject (fail-open #16)")
	}

	// Claimed "alice", proven "bob" -> mismatch, rejected (control, unchanged).
	ch2, id2 := mk()
	if _, err := CompleteCeremony(store, ch2, id2, "bob", now); err == nil {
		t.Fatal("mismatched proven identity must be rejected")
	}

	// Claimed "alice", proven "alice" -> issued (control, unchanged).
	ch3, id3 := mk()
	if _, err := CompleteCeremony(store, ch3, id3, "alice", now); err != nil {
		t.Fatalf("proven identity matching the claim must issue the grant: %v", err)
	}
}
