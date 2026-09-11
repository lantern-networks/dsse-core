package main

import (
	"strings"
	"testing"
)

func trustStoreAt(t *testing.T, serial int64, pems string) *transportTrustStore {
	t.Helper()
	s, err := openTransportTrustStore(t.TempDir()+"/trust.json", pems, serial, nil)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return s
}

// The fleet's distribution reaches an Edge from the control plane, forward only.
func TestAnEdgeAdoptsANewerDistributionFromTheControlPlane(t *testing.T) {
	pemA := string(makeBundleTestCA(t, "trust-a"))
	pemB := pemA + string(makeBundleTestCA(t, "trust-b"))
	edge := trustStoreAt(t, 7, pemA)
	_, held := edge.Current()

	if !edge.AdoptDistribution(transportTrustStoreState{Serial: held + 5, AnchorsPEM: pemB}) {
		t.Fatal("a newer distribution from the control plane was not adopted")
	}
	if got, serial := edge.Current(); serial != held+5 || !strings.Contains(got, "CERTIFICATE") {
		t.Fatalf("serial=%d anchors=%d bytes", serial, len(got))
	}
}

// ★★★ NEVER BACKWARDS. A device that has adopted an anchor must not find the Edge serving an older set — that
// is the direction that strands it, and the serial exists to make it impossible.
func TestAnOlderOrEqualDistributionIsNotAdopted(t *testing.T) {
	pem := string(makeBundleTestCA(t, "trust-a"))
	edge := trustStoreAt(t, 7, pem)
	_, held := edge.Current()
	for _, serial := range []int64{held, held - 1, 0} {
		if edge.AdoptDistribution(transportTrustStoreState{Serial: serial, AnchorsPEM: pem}) {
			t.Fatalf("serial %d was adopted over %d: a device that adopted the newer anchor is now talking to "+
				"an Edge serving an older set", serial, held)
		}
	}
}

// ★★★ NEVER EMPTY. Devices check these before they will talk to an Edge at all, so applying an empty
// distribution strands every one of them at once — and an empty section is what a control plane that has not
// been given a distribution publishes.
func TestAnEmptyDistributionIsNeverAdopted(t *testing.T) {
	pem := string(makeBundleTestCA(t, "trust-a"))
	edge := trustStoreAt(t, 7, pem)
	_, held := edge.Current()
	for _, anchors := range []string{"", "not a certificate", "-----BEGIN CERTIFICATE-----\nrubbish\n-----END CERTIFICATE-----\n"} {
		if edge.AdoptDistribution(transportTrustStoreState{Serial: held + 9, AnchorsPEM: anchors}) {
			t.Fatalf("an empty distribution was adopted: every device is now unable to reach this Edge")
		}
	}
	if _, serial := edge.Current(); serial != held {
		t.Fatalf("serial moved to %d", serial)
	}
}

// The snapshot is the store's own state shape, so the published document and the one the store keeps cannot
// describe the distribution differently — which is the failure the serial exists to prevent.
func TestTheSnapshotIsTheDistributionTheStoreIsServing(t *testing.T) {
	pem := string(makeBundleTestCA(t, "trust-a"))
	edge := trustStoreAt(t, 7, pem)
	snap := edge.Snapshot()
	got, serial := edge.Current()
	if snap.Serial != serial || snap.AnchorsPEM != got {
		t.Fatalf("the snapshot (serial %d) is not what the store serves (serial %d)", snap.Serial, serial)
	}
}

// ★ AND THE BUNDLE ACTUALLY CARRIES IT — published, applied, and folded into the generation. A section perfect
// at all but one of those never travels.
func TestTheBundlePublishesAppliesAndCountsTheTransportTrust(t *testing.T) {
	pub := readSourceFile(t, "admin_policy_routes.go")
	if !strings.Contains(pub, "bundle.TransportTrust = &transportTrustBundle{") {
		t.Fatal("the config bundle never carries the transport-trust distribution: the fleet goes on agreeing " +
			"about it through a shared file, which is nothing in a deployment that does not share one")
	}
	if !strings.Contains(pub, "+ transportTrustGen") {
		t.Fatal("the distribution's serial is not in the bundle's aggregate generation: a new distribution " +
			"would be published in every bundle and applied by nobody")
	}
	if !strings.Contains(readSourceFile(t, "config_bundle_sync.go"), "AdoptDistribution(") {
		t.Fatal("the Edge never applies the transport-trust section")
	}
}

// ★★★ THE AUTHORITY'S NUMBER AND THIS NODE'S NUMBER ARE NOT THE SAME NUMBER (2026-09-07, measured on a
// three-region deployment: the leading control plane answered 200 "added — serial 4", and ninety seconds
// later no Edge in any region had the certificate; all three still served serial 4 with the previous two).
//
// An Edge advances the serial itself whenever its announcement changes — which interception roots THIS node
// names is a property of this node, and devices adopt the whole document by serial, so it must. The authority
// never hears about those advances, so its counter runs behind, and the next certificate an operator adds is
// published at or below what the Edges already serve and discarded by every one of them as a replay.
func TestAnEdgeThatHasAdvancedItsOwnSerialStillTakesTheAuthoritysNextDistribution(t *testing.T) {
	pemA := string(makeBundleTestCA(t, "trust-a"))
	pemB := pemA + string(makeBundleTestCA(t, "trust-b"))
	// A real Edge signs what it serves; the announcement path only advances the serial when it can.
	edge, err := openTransportTrustStore(t.TempDir()+"/trust.json", pemA, 3,
		func(string, int64) (func(), error) { return func() {}, nil })
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	// This node advances on its own account, the way announcing its region's interception roots does.
	if _, changed, err := edge.AdvanceForAnnouncement([]string{"root=aaaa"}, "an interception root this node serves"); err != nil || !changed {
		t.Fatalf("announce: changed=%v err=%v", changed, err)
	}
	_, served := edge.Current()
	if served <= 3 {
		t.Fatalf("this test needs the node to have advanced past the authority, got %d", served)
	}

	// The authority, which never saw that, publishes its next distribution at ITS own count.
	if !edge.AdoptDistribution(transportTrustStoreState{Serial: 4, AnchorsPEM: pemB}) {
		t.Fatal("the authority's newest distribution was discarded because this node had counted further on " +
			"its own — an operator adds a certificate, the Console says added, and no Edge ever has it")
	}
	got, after := edge.Current()
	if len(parseAllCerts([]byte(got))) != 2 {
		t.Errorf("the authority's set was not taken: %d certificate(s)", len(parseAllCerts([]byte(got))))
	}
	if after <= served {
		t.Errorf("served serial went from %d to %d — devices adopt by serial, so a set they cannot see as "+
			"newer never reaches them", served, after)
	}

	// And the same authored distribution arriving again changes nothing.
	if edge.AdoptDistribution(transportTrustStoreState{Serial: 4, AnchorsPEM: pemB}) {
		t.Error("the same authored distribution was adopted twice, advancing the serial for a document that " +
			"did not change")
	}
}
