package main

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// ★★★ THE NAMES ARE DERIVED FROM THE SAME PLACE THE ENVIRONMENT FILE DERIVES THEM, or this check looks for
// names the deployment does not use and reports a problem that is not there — or worse, misses the one that
// is. Pinned against planeNamesFor, which is what the front door is configured from.
func TestTheNamesCheckedAreTheNamesTheDeploymentAnswersOn(t *testing.T) {
	const host = "deployment.example"
	got := planeNamesToResolve(host)
	front := planeNamesFor(host)
	for _, want := range []string{front.Admin, front.Agents, front.Console} {
		found := false
		for _, g := range got {
			if strings.EqualFold(g, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q is a name this deployment answers on and is not checked: %v", want, got)
		}
	}
}

// ★★★ A DEPLOYMENT IS REACHED BY NAME. Measured on a freshly minted one whose host was a real, resolvable
// machine: the host resolved and all four plane names did not, so the deployment was correct and unreachable,
// and nothing in the procedure said four DNS records were a prerequisite.
func TestNamesThatDoNotResolveAreNamed(t *testing.T) {
	const host = "deployment.example"
	// Only the bare host resolves — the shape that was measured.
	lookup := func(name string) ([]net.IP, error) {
		if name == host {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		}
		return nil, errors.New("no such host")
	}
	missing := unresolvedPlaneNames(host, lookup)
	if len(missing) != len(planeNamesToResolve(host)) {
		t.Fatalf("expected every plane name to be reported missing, got %v", missing)
	}

	// Control: when they all resolve, nothing is reported — so the report above is about resolution and not
	// about the way this test is written.
	all := func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil }
	if still := unresolvedPlaneNames(host, all); len(still) != 0 {
		t.Fatalf("names that resolve were reported as missing: %v", still)
	}

	// And a name that resolves to nothing counts as missing: an empty answer is not an answer.
	empty := func(string) ([]net.IP, error) { return nil, nil }
	if len(unresolvedPlaneNames(host, empty)) == 0 {
		t.Fatal("a name that resolves to no address was treated as resolvable")
	}
}
