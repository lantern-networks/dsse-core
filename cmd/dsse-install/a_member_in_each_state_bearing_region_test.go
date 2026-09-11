package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func renderShape(t *testing.T, shape machineShape) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := composeFileTo(dir, path, shape); err != nil {
		t.Fatalf("render: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// ★★★ THE SPLIT HAS TO ACTUALLY SPLIT (2026-08-31). The one-member store is derived from the whole one by
// cutting at the second member, so the two cannot drift apart — and a derivation that silently fails returns
// the WHOLE store, which would put three votes in every region instead of one. That failure would look like
// a working deployment until a region was lost, so it is checked directly.
func TestTheOneMemberStoreIsOneMember(t *testing.T) {
	// ★ MATCH THE SERVICE DEFINITION, NOT THE NAME. "dsse-store-b:" also appears inside the member list's
	// default value, so a looser matcher reports a cut that did not happen — and, the first time this ran,
	// reported one that DID happen as a failure. A check that cannot tell a definition from a mention is
	// testing the wrong file.
	one := composeConsensusStoreOneMember
	if !strings.Contains(one, "\n  dsse-store-a:") {
		t.Fatal("the one-member store does not define a member")
	}
	for _, other := range []string{"\n  dsse-store-b:", "\n  dsse-store-c:"} {
		if strings.Contains(one, other) {
			t.Fatalf("the derivation did not cut: a definition of%s is still in the one-member store, so every state-bearing "+
				"region would render three votes and losing one region would lose the quorum", other)
		}
	}
}

// ★★★ A MEMBER IN EACH STATE-BEARING REGION, WHICH IS WHAT THE STORE'S OWN COMMENT HAS ALWAYS SAID.
//
// What was rendered instead: three members in the founding region and none in a joining one, which makes a
// joining region a CLIENT of the founding region's store. Coherent, and not redundant — the founding
// region's loss takes the deployment's authority with it however many regions exist.
func TestEachStateBearingRegionRendersOneMemberWhenTheStoreSpansThem(t *testing.T) {
	founding := renderShape(t, machineShape{holds: regionShapeStateBearing, edges: true, storeSpansRegions: true})
	if !strings.Contains(founding, "\n  dsse-store-a:") {
		t.Error("the founding region renders no store member")
	}
	for _, other := range []string{"  dsse-store-b:", "  dsse-store-c:"} {
		if strings.Contains(founding, other) {
			t.Errorf("the founding region still defines%s: three votes here and one in each other region "+
				"means losing this region loses the quorum", other)
		}
	}
	if strings.Contains(founding, "depends_on: [dsse-store-a, dsse-store-b, dsse-store-c]") {
		t.Error("the database still waits for members this file does not define, which makes the project invalid")
	}

	joining := renderShape(t, machineShape{holds: regionShapeStateBearingJoin, edges: true, storeSpansRegions: true})
	if !strings.Contains(joining, "\n  dsse-store-a:") {
		t.Error("a joining state-bearing region renders no store member, so the store is still in one place")
	}
	if strings.Contains(joining, "  dsse-store-b:") {
		t.Error("a joining region renders more than one member")
	}
}

// ★ AND THE ONE-HOST REFERENCE IS UNTOUCHED. Three members on one host survives a container restart and
// loses everything with the host either way, so it stays the answer for a deployment that IS one host.
// ★★★ REVERSED BY THE OPERATOR (2026-09-03), on seeing what a one-machine deployment actually runs: three
// consensus members on one host protect against one etcd PROCESS dying while the machine lives — which is not
// what happens — and cost three processes, three data directories and three pairs of ports on the smallest
// shape this product ships. Worse, they read as redundancy: someone counting ports concludes the store can
// lose one, when what the deployment cannot lose is the single place it is in.
func TestAOneHostDeploymentRendersOneStoreMember(t *testing.T) {
	founding := renderShape(t, foundingShape)
	if !strings.Contains(founding, "\n  dsse-store-a:") {
		t.Error("the one-host shape renders no consensus store at all")
	}
	for _, m := range []string{"\n  dsse-store-b:", "\n  dsse-store-c:"} {
		if strings.Contains(founding, m) {
			t.Errorf("a one-machine deployment still renders %s — three votes in one place is not redundancy, "+
				"it is three processes that die together", m)
		}
	}
	if strings.Contains(founding, "depends_on: [dsse-store-a, dsse-store-b, dsse-store-c]") {
		t.Error("the database still waits for members that are no longer rendered")
	}
	joining := renderShape(t, machineShape{holds: regionShapeStateBearingJoin, edges: true})
	if strings.Contains(joining, "\n  dsse-store-a:") {
		t.Error("a joining region renders a store member without being told the store spans regions, which " +
			"would be a second cluster beside the deployment's one")
	}
}
