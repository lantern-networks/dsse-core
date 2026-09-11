package main

import (
	"strings"
	"testing"
)

// ★★★ A NODE THAT JOINS A SHARED, AUTOSCALED FLEET MUST BE ABLE TO SERVE WHAT THE FLEET ALREADY PROMISED.
//
// Measured 2026-08-20 on this repository's own scale-out definition: it carries none of the per-organization
// transport certificates. A device that has adopted its organization's anchor sends the announced name, the
// new node answers with the shared certificate, and the device refuses it — correctly. Scaling out under load
// would take offline exactly the devices the fleet grew to serve.
//
// Both directions matter more than usual here, because this one is FATAL: a false positive stops a healthy
// node from starting.
func TestANodeRefusesToJoinAFleetWhosePromisesItCannotKeep(t *testing.T) {
	// What a distribution's announcement actually looks like: fingerprints, per-organization anchors, names.
	announced := strings.Join([]string{
		"0ac681cd04f2d317",
		"tenant_northwind=9e3e8e20258b2ff5",
		"tenant_reference_lab=c9872b8d06e5ed66",
		"tenant_northwind@northwind.dsse.invalid",
		"tenant_reference_lab@lab.dsse.invalid",
		"recovery-sni=recovery.dsse.invalid",
		"recovery-endpoint=",
	}, ",")

	offersRecovery := func(name string) func(string) bool {
		return func(n string) bool { return name != "" && strings.EqualFold(n, name) }
	}
	serves := func(names ...string) func(string) bool {
		have := map[string]bool{}
		for _, n := range names {
			have[n] = true
		}
		return func(n string) bool { return have[n] }
	}

	// A node prepared with both organizations' certificates may join.
	if err := refuseToJoinFleetIfPromisesCannotBeKept(announced,
		serves("northwind.dsse.invalid", "lab.dsse.invalid"),
		offersRecovery("recovery.dsse.invalid")); err != nil {
		t.Fatalf("a fully prepared node was refused: %v", err)
	}

	// ★ THE SECOND MEASUREMENT: a node with both certificates and NO renewal-recovery path. It joined, dropped
	// "recovery-sni=" from the shared announcement and advanced the serial, so every device adopting it lost
	// the recovery name — and the dedicated port they would have fallen back to is closed.
	err := refuseToJoinFleetIfPromisesCannotBeKept(announced,
		serves("northwind.dsse.invalid", "lab.dsse.invalid"), offersRecovery(""))
	if err == nil {
		t.Fatal("a node that cannot offer the promised recovery name joined the fleet; every device that " +
			"adopts its announcement loses the only path back from an expired certificate")
	}
	if !strings.Contains(err.Error(), "recovery.dsse.invalid") {
		t.Fatalf("the refusal does not name the recovery promise: %v", err)
	}

	// The autoscaled node: no per-organization certificates at all.
	err = refuseToJoinFleetIfPromisesCannotBeKept(announced, serves(), offersRecovery(""))
	if err == nil {
		t.Fatal("a node with no per-organization certificate joined a fleet that has already told devices to " +
			"dial two names — every device holding that distribution would be refused by it")
	}
	for _, want := range []string{"northwind.dsse.invalid", "lab.dsse.invalid", "tenant_northwind", "tenant_reference_lab"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not name %q, so nobody can act on it: %v", want, err)
		}
	}

	// Half-prepared is still a hole, and it must name the half that is missing rather than the half that works.
	err = refuseToJoinFleetIfPromisesCannotBeKept(announced, serves("lab.dsse.invalid"),
		offersRecovery("recovery.dsse.invalid"))
	if err == nil {
		t.Fatal("a node missing one organization's certificate joined")
	}
	if !strings.Contains(err.Error(), "northwind.dsse.invalid") || strings.Contains(err.Error(), "promised the name lab.dsse.invalid") {
		t.Fatalf("the refusal names the wrong organization: %v", err)
	}

	// A fleet that announces no names at all — every deployment before roadmap D — must not be blocked.
	if err := refuseToJoinFleetIfPromisesCannotBeKept("0ac681cd,recovery-sni=withdrawn", serves(),
		offersRecovery("")); err != nil {
		t.Fatalf("a deployment that announces no per-organization name was refused: %v", err)
	}
	if err := refuseToJoinFleetIfPromisesCannotBeKept("", serves(), offersRecovery("")); err != nil {
		t.Fatalf("an empty announcement was refused: %v", err)
	}
}

// ★★★ THE NAME IS NOT ENOUGH: THE CERTIFICATE MUST CHAIN TO THE ANCHOR THE FLEET ANNOUNCED (2026-08-20).
//
// Found by running it. A node that fetched its material from the control plane served lab.dsse.invalid from a
// NEW authority while the fleet was still announcing the old one. It carried the name, so the name check said
// it was fine — and every device that reached it would have refused the certificate, because the anchor it
// holds did not sign it. This is the same shape as everything else this week: the promise was checked at the
// wrong grain.
func TestANodeMustServeTheANCHORTheFleetAnnounced(t *testing.T) {
	announced := strings.Join([]string{
		"tenant_reference_lab=" + strings.Repeat("a", 64),
		"tenant_reference_lab@lab.dsse.invalid",
	}, ",")
	serves := func(string) bool { return true }
	never := func(string) bool { return false }

	// Serving the announced anchor: fine.
	same := func(string) []string { return []string{strings.Repeat("A", 64)} }
	if err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(announced, serves, never, same, nil, nil); err != nil {
		t.Fatalf("a node serving exactly the announced anchor was refused: %v", err)
	}

	// Serving a DIFFERENT authority under the same name: refused, and it must say both fingerprints.
	other := func(string) []string { return []string{strings.Repeat("b", 64)} }
	err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(announced, serves, never, other, nil, nil)
	if err == nil {
		t.Fatal("a node serving the right NAME from the wrong AUTHORITY joined — every device of that " +
			"organization would refuse the certificate it presents")
	}
	if !strings.Contains(err.Error(), "aaaaaaaa") || !strings.Contains(err.Error(), "bbbbbbbb") {
		t.Fatalf("the refusal does not name what was announced and what would be served: %v", err)
	}

	// ★ THE CASE THAT TOOK A NODE DOWN: the fleet announces BOTH ends of a rotation and this node holds only
	// the old one — which every device also still holds, because that is what an overlap is. It must pass.
	bothAnnounced := announced + ",tenant_reference_lab=" + strings.Repeat("c", 64)
	if err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(bothAnnounced, serves, never,
		func(string) []string { return []string{strings.Repeat("a", 64)} }, nil, nil); err != nil {
		t.Fatalf("a node holding the OLD end of an announced overlap was refused: %v", err)
	}
	// And one that holds neither end is still refused.
	if err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(bothAnnounced, serves, never,
		func(string) []string { return []string{strings.Repeat("d", 64)} }, nil, nil); err == nil {
		t.Fatal("a node holding neither end of the announced overlap joined")
	}

	// ★ MID-ROTATION: this node holds BOTH ends of its own overlap, and the fleet announces one of them. It
	// must pass — refusing here would refuse every node in the middle of the rotation this mechanism exists to
	// perform.
	overlap := func(string) []string { return []string{strings.Repeat("b", 64), strings.Repeat("a", 64)} }
	if err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(announced, serves, never, overlap, nil, nil); err != nil {
		t.Fatalf("a node mid-rotation, holding both ends of its overlap, was refused: %v", err)
	}

	// A node that holds no anchor for that organization is covered by the NAME check, not this one — it must
	// not be reported twice, and it must not be silently excused either.
	none := func(string) []string { return nil }
	if err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(announced, serves, never, none, nil, nil); err != nil {
		t.Fatalf("a node with no anchor of its own was reported by the anchor check as well: %v", err)
	}
}

// ★★★ THE INCIDENT, AS A TEST (2026-08-20, reported from win-dev-1 after 31 minutes with no steering and no
// interception).
//
// The lab organization's overlap closed on evidence: every device reported holding the incoming authority, the
// node started serving it, and the withdrawn one left the announcement. Eight minutes later the node was
// restarted. Which authority it serves is rebuilt from disk, so it went back to presenting a certificate
// signed by the authority the fleet had just withdrawn — and the box that had adopted the new distribution
// refused it, disarmed steering, and ran on its native network until a person restarted a service.
//
// The guard was green throughout, because it asked whether this node HOLDS one of the announced authorities.
// It held the announced one — as incoming material it was not serving. Holding and presenting are two
// different facts and only the second is what a device meets.
func TestANodeThatWouldPresentAWithdrawnAuthorityIsRefused(t *testing.T) {
	withdrawn := strings.Repeat("c", 64)
	announcedNow := strings.Repeat("a", 64)
	announced := "tenant_reference_lab=" + announcedNow + ",tenant_reference_lab@lab.dsse.invalid"
	serves := func(string) bool { return true }
	never := func(string) bool { return false }
	holdsBoth := func(string) []string { return []string{withdrawn, announcedNow} }

	// What actually happened: it holds the announced authority and presents the withdrawn one.
	err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(announced, serves, never, holdsBoth,
		func(string) string { return withdrawn }, nil)
	if err == nil {
		t.Fatal("a node that would present a certificate signed by an authority the fleet has withdrawn was " +
			"admitted — its devices refuse the certificate they meet, which is the outage this guard exists " +
			"to prevent")
	}
	if !strings.Contains(err.Error(), "would be served") {
		t.Fatalf("the refusal does not say what the device would meet: %v", err)
	}

	// Presenting the announced one is the same node, one promotion later. It must pass.
	if err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(announced, serves, never, holdsBoth,
		func(string) string { return announcedNow }, nil); err != nil {
		t.Fatalf("a node presenting exactly what the fleet announces was refused: %v", err)
	}

	// Mid-overlap the fleet announces both, and a node presenting either end is serving something every
	// device holds — the state this mechanism exists to pass through.
	both := announced + ",tenant_reference_lab=" + withdrawn
	if err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(both, serves, never, holdsBoth,
		func(string) string { return withdrawn }, nil); err != nil {
		t.Fatalf("a node presenting the old end of an announced overlap was refused: %v", err)
	}
}
