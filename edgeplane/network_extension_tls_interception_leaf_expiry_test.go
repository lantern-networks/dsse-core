package edgeplane

import (
	"testing"
	"time"
)

// TestLabTLSLeafReMintedAfterExpiry reproduces the production cert error: a long-lived interception process
// (e.g. frozen across macOS sleep, alive past the 24h leaf validity) kept serving an expired leaf from
// leafCache because the serve path had no expiry check. The fix re-mints once the cached leaf is within the
// renew-before window of NotAfter.
func TestLabTLSLeafReMintedAfterExpiry(t *testing.T) {
	now := time.Date(2026, 6, 27, 8, 0, 0, 0, time.UTC)
	eng, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("construct interception: %v", err)
	}

	leaf1, err := eng.leafCertificate("", "host.example.com")
	if err != nil {
		t.Fatalf("first leaf: %v", err)
	}
	// Within validity the cache must be reused (no churn): same serial.
	leaf1b, err := eng.leafCertificate("", "host.example.com")
	if err != nil {
		t.Fatalf("cached leaf: %v", err)
	}
	if leaf1.Leaf.SerialNumber.Cmp(leaf1b.Leaf.SerialNumber) != 0 {
		t.Fatalf("leaf re-minted within validity (serials differ) — cache not reused")
	}

	// Advance the clock past the 24h leaf validity (the frozen-process scenario).
	now = now.Add(networkExtensionLabTLSLeafValidity + time.Hour)
	leaf2, err := eng.leafCertificate("", "host.example.com")
	if err != nil {
		t.Fatalf("post-expiry leaf: %v", err)
	}
	if leaf1.Leaf.SerialNumber.Cmp(leaf2.Leaf.SerialNumber) == 0 {
		t.Fatalf("expired cached leaf served instead of re-minting (same serial) — the bug")
	}
	if !now.Before(leaf2.Leaf.NotAfter) {
		t.Fatalf("re-minted leaf is already expired: NotAfter=%v now=%v", leaf2.Leaf.NotAfter, now)
	}
}
