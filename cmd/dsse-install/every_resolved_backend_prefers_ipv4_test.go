package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// every_resolved_backend_prefers_ipv4_test.go — every haproxy server line that RESOLVES a name must resolve it
// to IPv4.
//
// ★★★ WHY, AND WHY THE TEST IS THIS SHAPE (2026-08-31, after a fresh install failed nine checks with one
// cause and the fix for it was already in the tree).
//
// An Edge decides whether to believe a PROXY protocol header by the SOURCE ADDRESS it arrives from
// (-trusted-front-doors). Once the container network carries IPv6, Docker's DNS answers AAAA, haproxy
// re-resolves its backends to their v6 addresses, and the doorway's source address becomes one nobody told the
// Edge to trust. The Edge then drops every connection as it arrives: haproxy logs SD, the door presents no
// certificate for any name, and every check that needs a device fails with a bare "EOF". Nothing names it.
//
// That was diagnosed on 2026-08-30 and fixed the same evening — in frontdoor.go, which renders the control
// plane, console and database doors. The AGENT plane's server lines are rendered by edgeFleetServers, in
// another file, and were missed. The next deployment came up with the fix applied to every door a device does
// not use, and presented no certificate to any device.
//
// So this test does not check a function. It reads EVERY generator in this package and requires the property
// of every line that has `resolvers`, wherever it is written. A test that named the two call sites would have
// to be edited by whoever adds the third.
func TestEveryResolvedBackendPrefersIPv4(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing this package: %v", err)
	}
	// A server line as it appears in a Go string literal, up to the closing quote or a newline escape. It
	// must look like one — "server <name> <host>:<port> … resolvers containers" — so that prose ABOUT
	// resolvers is not mistaken for a directive that uses them. The first version of this matched a comment
	// in plan.go saying server lines carry no resolvers, and failed on it.
	line := regexp.MustCompile(`server [A-Za-z0-9_%+-]+ [^ "\n]+:[0-9]+[^"\n]*resolvers containers[^"\n]*`)
	checked := 0
	for _, src := range sources {
		if strings.HasSuffix(src, "_test.go") {
			continue
		}
		raw, rerr := os.ReadFile(src)
		if rerr != nil {
			t.Fatalf("reading %s: %v", src, rerr)
		}
		for _, m := range line.FindAllString(string(raw), -1) {
			checked++
			if !strings.Contains(m, "resolve-prefer ipv4") {
				t.Errorf("%s renders a backend that resolves a name without resolve-prefer ipv4:\n    %s\n"+
					"Once the network carries IPv6 this resolves to a v6 address, the doorway's source address "+
					"changes, and the Edge stops believing the PROXY header from it — every connection is "+
					"dropped on arrival and the door presents no certificate to anybody.", src, strings.TrimSpace(m))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no resolved backend lines were found at all — this test is no longer reading the generators, " +
			"which makes it pass for the wrong reason")
	}
	t.Logf("%d resolved backend line(s) across this package", checked)
}
