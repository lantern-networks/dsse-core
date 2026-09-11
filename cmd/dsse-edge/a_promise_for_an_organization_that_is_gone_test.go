package main

import (
	"strings"
	"testing"
)

// ★★★ THE NODE HAD THE ANSWER IN ITS HANDS AND KILLED ITSELF ANYWAY (2026-09-07).
//
// Eighteen organizations were deleted through the Console. Hours later an unrelated build roll restarted the
// Edges and every one of them, in all three regions, exited on the same line — one line below the line that
// said it knew which organizations the deployment had:
//
//	tenant_edge_material installed: transport for 20 organization(s), interception for 20, device identity for 20
//	REFUSING TO JOIN THIS FLEET: this node cannot keep 18 promise(s) …
//
// The guard could already tell "the name is gone" from "I am behind" — but only via an ANNOUNCED ANCHOR held
// for that organization, and a DELETED organization has no anchor here at all. So every deletion landed on the
// refusal, and the refusal is fatal, and the announcement is shared, so it is the whole fleet at once.
//
// A successful answer that does not mention an organization at all settles exactly the question the guard
// could not answer.

func goneExcept(live ...string) func(string) bool {
	known := map[string]bool{}
	for _, t := range live {
		known[strings.ToLower(t)] = true
	}
	return func(tenant string) bool { return !known[strings.ToLower(strings.TrimSpace(tenant))] }
}

func TestAPromiseForADeletedOrganizationIsRetractedNotRefused(t *testing.T) {
	// This node serves one organization and the announcement still promises a second that was deleted — the
	// shape of the outage, with the numbers made small.
	const announced = "tenant_live@live.dsse.invalid,tenant_deleted@deleted.dsse.invalid"
	serves := func(name string) bool { return name == "live.dsse.invalid" }
	never := func(string) bool { return false }
	noAnchors := func(string) []string { return nil }

	// Before: the control plane has said nothing, so the node cannot tell a deletion from its own ignorance.
	// It refuses, and that is still right.
	if err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(announced, serves, never, noAnchors, nil, nil); err == nil {
		t.Fatal("with no answer from the control plane, a promise this node cannot keep must still refuse — " +
			"absence of an answer is not a withdrawal")
	}

	// After: the control plane's last answer named tenant_live and did not mention tenant_deleted.
	err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(announced, serves, never, noAnchors, nil,
		goneExcept("tenant_live"))
	if err != nil {
		t.Fatalf("a promise for an organization the control plane no longer has must be RETRACTED, not "+
			"refused — refusing it is what took three regions down at once: %v", err)
	}
}

// The organization still exists and this node simply lacks its certificate: that is a node that is behind, and
// it must still refuse. This is the case the guard was written for and the one the fix must not eat.
func TestAPromiseForALiveOrganizationStillRefuses(t *testing.T) {
	const announced = "tenant_live@live.dsse.invalid,tenant_other@other.dsse.invalid"
	serves := func(name string) bool { return name == "live.dsse.invalid" }
	never := func(string) bool { return false }
	noAnchors := func(string) []string { return nil }

	err := refuseToJoinFleetIfPromisesCannotBeKeptWithAnchors(announced, serves, never, noAnchors, nil,
		goneExcept("tenant_live", "tenant_other"))
	if err == nil {
		t.Fatal("this node holds no certificate for an organization the deployment still has — it would " +
			"refuse that organization's devices, which is exactly what this guard exists to prevent")
	}
	if !strings.Contains(err.Error(), "tenant_other") {
		t.Fatalf("the refusal must name the organization it is about: %v", err)
	}
}

// OrganizationIsGone is false until a successful, non-empty answer has arrived, and an empty answer never
// replaces one. A control plane that is still assembling answers 200 with nothing in it, and reading that as
// "the deployment has no organizations" would retract every promise in the fleet.
func TestAnEmptyOrMissingAnswerRetractsNothing(t *testing.T) {
	f := &tenantTransportMaterialFetcher{}
	if f.OrganizationIsGone("tenant_anything") {
		t.Fatal("with no answer at all, no organization is gone")
	}
	empty := map[string]bool{}
	f.lastAnswer.Store(&empty)
	if f.OrganizationIsGone("tenant_anything") {
		t.Fatal("an answer that carried nothing is not evidence that the deployment is empty")
	}
	known := map[string]bool{"tenant_live": true}
	f.lastAnswer.Store(&known)
	if f.OrganizationIsGone("tenant_live") {
		t.Fatal("an organization the answer named is not gone")
	}
	if !f.OrganizationIsGone("tenant_deleted") {
		t.Fatal("an organization a non-empty answer did not mention is gone")
	}
}
