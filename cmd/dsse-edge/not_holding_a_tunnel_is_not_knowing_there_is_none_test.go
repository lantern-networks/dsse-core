package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// ★★★ A SITE WITH TWO LIVE CONNECTORS READ "DOWN — 0 OF 2 CONNECTORS ONLINE" (2026-09-01, found on the
// Console, which is the only place it could be found).
//
// adminConnectorOnline takes a non-nil tunnel_connected as authoritative and never looks at the heartbeat. The
// control plane terminates no connector tunnel at all, so a resolver that answered "false" for anything it did
// not hold made every connector in the deployment permanently offline on the only screen an operator has —
// while both were serving flows to a private asset.
//
// The rule this restores is the one already written beside the resolver type: never assert a false
// "disconnected". Yes when this node holds it; UNKNOWN when it does not, because a node cannot tell "nobody
// holds it" from "a sibling holds it".
func TestAnUnheldConnectorIsUnknownAndFallsThroughToTheHeartbeat(t *testing.T) {
	now := time.Date(2026, 9, 1, 2, 45, 0, 0, time.UTC)
	fresh := now.Add(-10 * time.Second).Format(time.RFC3339)
	stale := now.Add(-24 * time.Hour).Format(time.RFC3339)

	// Unknown + a fresh heartbeat = online. This is the case the Console got wrong: a connector held by a
	// sibling Edge, read at the control plane, which holds no tunnels of its own.
	if !adminConnectorOnline(adminConnector{LastHeartbeatAt: fresh}, now) {
		t.Error("a connector with an unknown tunnel and a fresh heartbeat read as offline — this is the site " +
			"that showed Down while both of its connectors were serving flows")
	}
	// Unknown + a stale heartbeat is still offline: the fix must not turn "we do not know" into "it is fine".
	if adminConnectorOnline(adminConnector{LastHeartbeatAt: stale}, now) {
		t.Error("a connector last heard from a day ago read as online")
	}
	// And a node that DOES hold the tunnel still says so, which is the stronger fact when it exists.
	yes := true
	if !adminConnectorOnline(adminConnector{TunnelConnected: &yes, LastHeartbeatAt: stale}, now) {
		t.Error("a node holding the tunnel was not believed")
	}
}

// ★ AND THE RESOLVER ITSELF NEVER SAYS FALSE. Read from the source, because the defect was the VALUE one
// closure returned — every unit test of the readers passed while the deployment showed every connector down.
func TestTheTunnelResolverNeverAssertsDisconnected(t *testing.T) {
	src := readEdgeSource(t, "main.go")
	i := indexOf(src, "connectorTunnelStatus := func(connectorID string) *bool {")
	if i < 0 {
		t.Fatal("the tunnel-status resolver moved or was renamed; update this guard deliberately")
	}
	body := src[i : i+700]
	if strings.Contains(body, "connected := ok") {
		t.Error("the resolver returns its local answer as a fact both ways: on a control plane, which holds no " +
			"connector tunnel at all, that is a false 'disconnected' for every connector in the deployment")
	}
}

func indexOf(s, sub string) int { return strings.Index(s, sub) }

// ★★★ AND THE SCREEN IS SENT THE ANSWER, NOT THE INGREDIENTS (2026-09-01, seen on the Console after the fix
// above landed).
//
// The Sites screen read tunnel_connected as a boolean. The moment that field learned a third state — unknown,
// which is what a node answers about a connector it does not hold and what a CONTROL PLANE answers about every
// connector — the screen read unknown as offline. It showed "Healthy … 0 / 2 connectors online" with a
// heartbeat eight seconds old beside each Offline row, while the API it had just called said online=2.
//
// A rule kept in two places disagrees the first time one of them learns something.
func TestTheConnectorDTOCarriesTheOnlineAnswerItself(t *testing.T) {
	now := time.Now().UTC()
	dto := adminConnector{ID: "conn-x", LastHeartbeatAt: now.Add(-5 * time.Second).Format(time.RFC3339)}
	applyConnectorTunnelStatus(&dto, nil) // no tunnel manager: tunnel_connected stays unknown
	if dto.TunnelConnected != nil {
		t.Fatalf("tunnel_connected = %v, want unknown", *dto.TunnelConnected)
	}
	if !dto.Online {
		t.Error("a connector heard from five seconds ago is not marked online, so a screen reading this field " +
			"shows Offline beside a fresh heartbeat")
	}

	stale := adminConnector{ID: "conn-y", LastHeartbeatAt: now.Add(-48 * time.Hour).Format(time.RFC3339)}
	applyConnectorTunnelStatus(&stale, nil)
	if stale.Online {
		t.Error("a connector last heard from two days ago is marked online")
	}
}

// ★ AND THE SCREEN USES IT. Read from the file, because the defect was a screen computing its own answer from
// a field whose meaning had changed underneath it — no Go test could have seen that.
func TestTheSitesScreenReadsTheServersAnswer(t *testing.T) {
	body, err := os.ReadFile("../../console/sites.js")
	if err != nil {
		t.Fatalf("read sites.js: %v", err)
	}
	src := string(body)
	if strings.Contains(src, "c.tunnel_connected)") {
		t.Error("the Sites screen still decides online from tunnel_connected, which has three states and is " +
			"unknown for every connector when read at a control plane")
	}
	if !strings.Contains(src, "c.online") {
		t.Error("the Sites screen does not read the server's own online answer")
	}
}
