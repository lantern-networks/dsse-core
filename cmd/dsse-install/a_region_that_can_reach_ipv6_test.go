package main

import (
	"os"
	"strings"
	"testing"
)

// a_region_that_can_reach_ipv6_test.go — a generated region can reach an IPv6-only origin, and the two halves
// of that cannot drift apart.
//
// ★★★ WHY BOTH HALVES (2026-08-30, measured by breaking a running lab with one of them). An Edge with no IPv6
// source address answers an IPv6-only name with 502 — "connect: cannot assign requested address" — and answers
// a DUAL-STACK name with 200, because it silently drops to v4. A device sees 200 either way, so a device is
// not where this can be measured.
//
// Giving the container network IPv6 is half. The other half is that Docker's DNS then answers AAAA, the front
// door re-resolves its backends to their v6 addresses, and the door's SOURCE address changes — while an Edge
// trusts a PROXY protocol header only from the door addresses it was told, which this deployment assigns by
// hand in v4. Both regions then present NO CERTIFICATE AT ALL, for any name, with nothing naming the cause.

func TestTheGeneratedNetworkCarriesIPv6(t *testing.T) {
	source := readSourceFile(t, "compose.go")
	if !strings.Contains(source, "enable_ipv6: true") {
		t.Error("the generated container network has no IPv6, so every Edge in it answers an IPv6-only origin " +
			"with 'cannot assign requested address' and drops dual-stack traffic to v4 without saying so")
	}
	if !strings.Contains(source, "DSSE_SUBNET_V6") {
		t.Error("the network declares IPv6 with no subnet to allocate from")
	}
	// ★ The ULA reaches the world only through the daemon's NAT66, which is a HOST setting this file cannot
	// make. Saying so where the network is declared is what keeps a deployment from shipping a network whose
	// addresses route nowhere.
	if !strings.Contains(source, "ip6tables") {
		t.Error("nothing beside the generated network says the host daemon must carry ip6tables, so a " +
			"deployment can be handed a network whose addresses reach nothing")
	}
}

func TestTheFrontDoorReachesItsNodesOverIPv4(t *testing.T) {
	source := readSourceFile(t, "frontdoor.go")
	lines := strings.Split(source, "\n")
	backends, pinned := 0, 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "server ") || !strings.Contains(trimmed, "resolvers containers") {
			continue
		}
		backends++
		if strings.Contains(trimmed, "resolve-prefer ipv4") {
			pinned++
		}
	}
	if backends == 0 {
		t.Fatal("the front door template has no resolved backends — this check is looking at the wrong file")
	}
	if pinned != backends {
		t.Errorf("%d of %d front-door backends are not pinned to IPv4: once the network carries IPv6 those "+
			"re-resolve to v6, the door's source address changes, and every Edge refuses it — the region then "+
			"presents no certificate for any name", backends-pinned, backends)
	}
}

// readSourceFile reads one of this package's own files. The generated artefacts are strings in these files,
// so the assertions above are about what a deployment will be handed, not about a fixture.
func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
