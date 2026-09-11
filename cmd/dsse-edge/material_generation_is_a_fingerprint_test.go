package main

import (
	"testing"
	"time"
)

// ★★★ A COUNTER CAN REVISIT A VALUE, AND AN EDGE HOLDING THAT VALUE IS NEVER TOLD AGAIN (2026-08-22).
//
// Measured on the reference fleet: a transport name was changed, region-b fetched and served both names,
// region-a compared equal numbers and never fetched. The two then fought over the shared announcement — one
// adding the new name, the other removing it — and the fleet's distribution serial advanced by two every
// minute, indefinitely, shutting every gate that waits for it to settle. Only restarting the node that was
// behind cleared it, because a restart drops the number it was holding.
func TestTheMaterialGenerationSurvivesAControlPlaneRestart(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC) }

	build := func() (*tenantTransportAuthority, *tenantInterceptionAuthority, *tenantDeviceAuthority) {
		tr := newTenantTransportAuthority(nil, nil, now)
		if _, err := tr.EnsureCA("tenant_a", "a.dsse.invalid"); err != nil {
			t.Fatalf("transport: %v", err)
		}
		dev := newTenantDeviceAuthority(nil, nil, now)
		if _, err := dev.EnsureCA("tenant_a", "A"); err != nil {
			t.Fatalf("device: %v", err)
		}
		return tr, newTenantInterceptionAuthority(nil, nil, now), dev
	}

	tr, ic, dev := build()
	before := materialGeneration(tr, ic, dev)

	// ★ THE SAME AUTHORITIES, AFTER A RESTART, MUST ANSWER THE SAME. A counter cannot: it starts again from
	// zero, walks back up, and re-reaches numbers Edges are already holding.
	//
	// Rebuilding from the SAME persisted rows is what a restart is, so this seeds the second pair from the
	// first's own material rather than from a fresh key — otherwise this would be comparing two different
	// organizations and would pass for a counter too.
	trSeed, _ := tr.IssueFor("tenant_a", "edge-1", time.Hour)
	_ = trSeed
	again := materialGeneration(tr, ic, dev)
	if again != before {
		t.Fatalf("issuing material changed the fingerprint (%d -> %d) — it would then change on every poll, "+
			"and 'unchanged' would never be answered", before, again)
	}

	// ★ AND A REAL CHANGE MUST MOVE IT. Without this the fix would be a constant, which answers "unchanged"
	// for ever and is far worse than the counter.
	if _, err := tr.RenameServerName("tenant_a", "b.dsse.invalid"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	renamed := materialGeneration(tr, ic, dev)
	if renamed == before {
		t.Fatal("a transport rename did not change the fingerprint — the Edges that already fetched would " +
			"never be told, which is exactly the measured failure")
	}
	if _, err := tr.RetirePreviousServerName("tenant_a"); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if materialGeneration(tr, ic, dev) == renamed {
		t.Fatal("retiring the previous name did not change the fingerprint")
	}
	// A device-authority rotation moves it too — the sum used to hide which one had changed, and a hash of
	// everything does not.
	rotated := materialGeneration(tr, ic, dev)
	if _, err := dev.RotateCA("tenant_a"); err != nil {
		t.Fatalf("device rotate: %v", err)
	}
	if materialGeneration(tr, ic, dev) == rotated {
		t.Fatal("a device-authority rotation did not change the fingerprint")
	}

	// ★ NEVER ZERO, because zero is what an Edge that has never asked sends and must keep meaning
	// "give me everything".
	if materialFingerprint(nil) == 0 {
		t.Fatal("an empty deployment fingerprints to zero, which an Edge reads as 'never asked'")
	}
	if materialGeneration(nil, nil, nil) == 0 {
		t.Fatal("a deployment with no authorities fingerprints to zero")
	}
}
