package main

import (
	"crypto/x509"
	"net"
	"testing"
)

// ★★★ ADDING A NAME MUST NOT REMOVE ONE (2026-09-03, measured by running -add-host on a three-region
// deployment and redistributing what it produced: every per-region plane name was gone from the leaves, and
// the region doors, the inter-region mesh and the control-plane links failed together on the next restart).
func TestAddHostKeepsPerRegionPlaneNames(t *testing.T) {
	// What a three-region deployment's leaf carries.
	carried := []string{
		"keyaki.lab",
		"agents.keyaki.lab", "admin.keyaki.lab", "console.keyaki.lab", "recovery.keyaki.lab", "authority.keyaki.lab",
		"agents.osaka.keyaki.lab", "admin.osaka.keyaki.lab", "console.osaka.keyaki.lab",
		"authority.osaka.keyaki.lab", "recovery.osaka.keyaki.lab",
		"agents.tokyo-east.keyaki.lab", "admin.tokyo-east.keyaki.lab",
		"node-osaka.keyaki.lab", "node-tokyo-east.keyaki.lab",
		"localhost", "*.admin.keyaki.lab", "dsse-edge-a",
	}
	kept, _, err := hostsInCertificateFrom(&x509.Certificate{DNSNames: carried})
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]bool{}
	for _, n := range kept {
		in[n] = true
	}
	// The deployment-wide plane names are re-derived from the deployment name, so they are correctly dropped.
	for _, n := range []string{"agents.keyaki.lab", "admin.keyaki.lab"} {
		if in[n] {
			t.Errorf("%s was kept, but the issuer re-derives it — keeping it is how a name gets re-prefixed", n)
		}
	}
	// The PER-REGION ones are re-derived by nothing: their host (osaka.keyaki.lab) is in no list.
	for _, n := range []string{
		"agents.osaka.keyaki.lab", "admin.osaka.keyaki.lab", "console.osaka.keyaki.lab",
		"authority.osaka.keyaki.lab", "recovery.osaka.keyaki.lab",
		"agents.tokyo-east.keyaki.lab", "admin.tokyo-east.keyaki.lab",
	} {
		if !in[n] {
			t.Errorf("%s was dropped — adding one name would delete it from every leaf, and the region's "+
				"door, the mesh and the control-plane links fail together on the next restart", n)
		}
	}
	// And the machine names survive, as they always did.
	for _, n := range []string{"node-osaka.keyaki.lab", "node-tokyo-east.keyaki.lab", "keyaki.lab"} {
		if !in[n] {
			t.Errorf("%s was dropped", n)
		}
	}
}

// ★ AND WHATEVER THE RECONSTRUCTION STILL MISSES IS SAID OUT LOUD, before anything is written.
func TestAddHostNamesWhatItWouldStopServing(t *testing.T) {
	current := &x509.Certificate{DNSNames: []string{
		"keyaki.lab", "agents.osaka.keyaki.lab", "node-osaka.keyaki.lab", "localhost",
	}}
	lost := namesThatWouldStopBeingServed(current, []string{"keyaki.lab", "node-osaka.keyaki.lab"}, []net.IP{})
	if len(lost) != 1 || lost[0] != "agents.osaka.keyaki.lab" {
		t.Fatalf("expected the per-region plane name to be reported as lost, got %v", lost)
	}
	// Nothing is "lost" when the next issue carries everything the current one does.
	none := namesThatWouldStopBeingServed(current,
		[]string{"keyaki.lab", "node-osaka.keyaki.lab", "agents.osaka.keyaki.lab"}, []net.IP{})
	if len(none) != 0 {
		t.Errorf("reported names as lost that will still be served: %v", none)
	}
}
