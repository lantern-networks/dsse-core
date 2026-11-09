package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// The state region-b was in on 0.4.1 acceptance B at 01:53:49: the connector had just left this node, the
// catalogue still said it was here, and region-a — where it had gone — was one mesh link away.
func departedConnectorScene(t *testing.T, departures *connectorDepartureLog) (*connector.Registry, edgeplane.ConnectorEgressDialer, *recordingDirectDialer) {
	t.Helper()
	reg := connector.NewRegistry()
	if _, err := reg.Register(model.ConnectorRegistration{
		ID: "conn-home", TenantID: "tenant-a", Status: "active", PrivateBaseURL: "https://internal.invalid",
		EdgeRegionID: "region-a", ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: []string{"corp.internal"}},
	}, time.Date(2026, 11, 7, 1, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := reg.RecordAttachedRegion("tenant-a", "conn-home", "region-b"); err != nil {
		t.Fatalf("record where it was: %v", err)
	}

	// The region-a Edge, which now holds the connector, at the far end of the mesh link.
	manager := tunnel.NewManager()
	edgeRaw, peerRaw := net.Pipe()
	t.Cleanup(func() { edgeRaw.Close(); peerRaw.Close() })
	link, _ := manager.Register("peer-region-a", "tun-mesh", tunnel.NewInProcessConn(edgeRaw, true))
	go link.Run()
	startFakeConnectorEcho(tunnel.NewInProcessConn(peerRaw, false))

	direct := &recordingDirectDialer{}
	dialer := edgeplane.ConnectorEgressDialer{
		ResolveConnector: connectorDestinationResolver(reg),
		Tunnels:          tunnelsThatRememberDepartures{Manager: tunnel.NewManager(), departures: departures},
		TenantID:         "tenant-a",
		LocalRegion:      "region-b",
		PeerEdges:        stubPeerEdges{region: "region-a", session: link},
		Direct:           direct,
	}
	return reg, dialer, direct
}

func openCorpHost(dialer edgeplane.ConnectorEgressDialer) (io.ReadWriteCloser, error) {
	return dialer.OpenTCPConnection(context.Background(), edgeplane.NetworkExtensionRuntimeCopyTCPRoute{
		Host: "app.corp.internal", Port: 443, SNI: "app.corp.internal", TenantID: "tenant-a",
	})
}

// ★★★ THE FLOW IS HELD UNTIL THE DEPLOYMENT SAYS WHERE THE CONNECTOR WENT, AND THEN IT GOES THERE. Before
// this, the same flow was refused at once — one of 109 measurements on acceptance B.
func TestAFlowForAConnectorThatJustLeftIsHeldUntilTheDeploymentSaysWhereItWent(t *testing.T) {
	departures := newConnectorDepartureLog(5*time.Second, 0)
	reg, dialer, direct := departedConnectorScene(t, departures)
	departures.departed("conn-home")

	const learnAfter = 150 * time.Millisecond
	go func() {
		time.Sleep(learnAfter)
		if _, err := reg.RecordAttachedRegion("tenant-a", "conn-home", "region-a"); err != nil {
			t.Errorf("record where it went: %v", err)
		}
		departures.learned("conn-home")
	}()

	started := time.Now()
	conn, err := openCorpHost(dialer)
	if err != nil {
		t.Fatalf("a flow for a connector that was moving between Regions was refused: %v", err)
	}
	defer conn.Close()
	if waited := time.Since(started); waited < learnAfter {
		t.Fatalf("the flow was carried after %s, before the deployment said where the connector went — it cannot "+
			"have gone the right way", waited)
	}
	if direct.called {
		t.Fatal("a destination a connector fronts was dialled directly")
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "PING" {
		t.Fatalf("the flow did not reach the connector over the mesh to region-a: %q %v", buf, err)
	}
}

// ★ A CONNECTOR THIS NODE NEVER HELD IS REFUSED AT ONCE. "No tunnel here" is a move only where this node saw
// the tunnel end; anywhere else it is the ordinary refusal and must not start costing every flow a wait.
func TestAConnectorThisNodeDidNotJustLoseIsRefusedAtOnce(t *testing.T) {
	departures := newConnectorDepartureLog(5*time.Second, 0)
	_, dialer, _ := departedConnectorScene(t, departures)

	started := time.Now()
	if _, err := openCorpHost(dialer); err == nil {
		t.Fatal("a connector with no tunnel here and a catalogue naming this region was served")
	}
	if waited := time.Since(started); waited > time.Second {
		t.Fatalf("a refusal that has nothing to wait for took %s", waited)
	}
}

// ★ AND ONE THAT DOES NOT COME BACK COSTS THE WAIT, THEN THE SAME REFUSAL. The wait is bounded by the
// departure, not by how many flows arrive or how often they retry.
func TestAConnectorThatDoesNotComeBackIsRefusedWhenTheWaitIsOver(t *testing.T) {
	const window = 300 * time.Millisecond
	departures := newConnectorDepartureLog(window, 0)
	_, dialer, _ := departedConnectorScene(t, departures)
	departures.departed("conn-home")

	// News that changes nothing — an ordinary pull — wakes the flow, which looks again and goes on waiting.
	go func() {
		time.Sleep(window / 3)
		departures.announce()
	}()
	started := time.Now()
	if _, err := openCorpHost(dialer); err == nil {
		t.Fatal("a connector nobody has heard from since it left was served")
	}
	waited := time.Since(started)
	if waited < window-50*time.Millisecond || waited > window+time.Second {
		t.Fatalf("the refusal came after %s; it should come when the %s wait is over", waited, window)
	}
	if departures.await(context.Background(), "conn-home") {
		t.Fatal("a departure whose wait is over is still being waited for")
	}
}

// ★★ THE EARLY PULLS FOLLOW THE DEPARTURE, NOT THE TRAFFIC. A handful per departure, doubling, and none once
// the answer has moved.
func TestADepartureAsksForAFewEarlyPullsAndStopsWhenItLearns(t *testing.T) {
	count := func(d *connectorDepartureLog, for_ time.Duration) int {
		n := 0
		deadline := time.After(for_)
		for {
			select {
			case <-d.hurryRequests():
				n++
			case <-deadline:
				return n
			}
		}
	}

	d := newConnectorDepartureLog(400*time.Millisecond, 50*time.Millisecond)
	d.departed("conn-x")
	// 50, 100, 200 ms — and not 400, which is the end of the wait.
	if got := count(d, 600*time.Millisecond); got != 3 {
		t.Fatalf("a departure asked for %d early pulls, want 3 (one at 50ms, then doubling within a 400ms wait)", got)
	}

	learning := newConnectorDepartureLog(400*time.Millisecond, 50*time.Millisecond)
	learning.departed("conn-y")
	go func() {
		time.Sleep(70 * time.Millisecond)
		learning.learned("conn-y")
	}()
	if got := count(learning, 600*time.Millisecond); got > 1 {
		t.Fatalf("the departure went on asking for %d early pulls after the answer had moved", got)
	}

	back := newConnectorDepartureLog(400*time.Millisecond, 50*time.Millisecond)
	back.departed("conn-z")
	back.arrived("conn-z")
	if got := count(back, 300*time.Millisecond); got != 0 {
		t.Fatalf("a connector that came straight back still caused %d early pulls", got)
	}
}

// ★ AN EARLY PULL HAPPENS NOW, NOT AT THE NEXT TICK, AND EVERY PULL WAKES WHAT IS WAITING.
func TestTheConfigurationPullRunsEarlyWhenAskedAndSaysWhenItHasPulled(t *testing.T) {
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls.Add(1)
		_ = json.NewEncoder(w).Encode(configBundlePayload{Generation: 1, Epoch: "early-pull"})
	}))
	defer server.Close()

	hurry := make(chan struct{}, 1)
	var pulled atomic.Int32
	src := configBundleSource{tenantID: "tenant_lab_001", url: server.URL, client: server.Client(),
		interval: time.Hour, status: &configBundleSyncStatus{}, hurry: hurry, pulled: func() { pulled.Add(1) }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go src.run(ctx, configApplyTargets{policyStore: policy.NewStore(nil)})

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("%s: polls=%d pulled=%d", what, polls.Load(), pulled.Load())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor("the first pull", func() bool { return pulled.Load() == 1 })
	hurry <- struct{}{}
	waitFor("an early pull an hour before the tick", func() bool { return polls.Load() == 2 && pulled.Load() == 2 })
}

// ★★★ ONLY THE NODE HOLDING THE TUNNEL TELLS THE AUTHORITY WHERE THE CONNECTOR IS. The authority takes the
// last report as the truth, so a heartbeat landing on the node the connector is leaving must not be one.
func TestOnlyANodeHoldingTheTunnelReportsWhereTheConnectorIs(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	start := strings.Index(src, `mux.HandleFunc("POST /connectors/{connector_id}/heartbeat"`)
	if start < 0 {
		t.Fatal("the connector heartbeat handler is not where this test looks for it")
	}
	handler := src[start:]
	if end := strings.Index(handler, "\n\tmux.HandleFunc("); end > 0 {
		handler = handler[:end]
	}
	guard := strings.Index(handler, "if _, holdsItsTunnel := tunnelManager.Get(conn.ID); holdsItsTunnel {")
	withRegion := strings.Index(handler, "connectorCPReport.Report(connectorReport{Registration: conn, TenantID: conn.TenantID,\n\t\t\t\t\tAttachedRegionID: evaluator.EdgeRegionID})")
	livenessOnly := strings.Index(handler, "connectorCPReport.Report(connectorReport{Registration: conn, TenantID: conn.TenantID, LivenessOnly: true})")
	if guard < 0 || withRegion < 0 || withRegion < guard {
		t.Fatal("a heartbeat reports this region as where the connector is without this node holding its tunnel")
	}
	// ★ AND A NODE WITHOUT THE TUNNEL STILL SAYS THE CONNECTOR IS ALIVE (review of 2026-11-07): the multi-node
	// layouts balance the agent door by least connections, so the heartbeat can land on any node of the region.
	if livenessOnly < 0 || livenessOnly < withRegion {
		t.Fatal("a heartbeat on a node without the tunnel carries nothing, so the authority's last_heartbeat freezes")
	}
	if strings.Count(handler, "connectorCPReport.Report(") != 2 {
		t.Fatal("the heartbeat handler reports to the authority on a path this test does not see")
	}
}

// ★ THE DEVICE PATHS WAIT; THE MESH INGRESS DOES NOT. A relayed flow cannot be relayed onward, so holding it
// at the node the connector left only delays the same refusal.
func TestTheDevicePathsWaitForAMoveAndTheMeshIngressDoesNot(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if n := strings.Count(src, "egressTunnels, networkExtensionRuntimeCopyTenantID"); n != 2 {
		t.Errorf("the intercept and browser-engine paths: %d of 2 use the departure-aware tunnels", n)
	}
	if !strings.Contains(src, "\t\tTunnels:          egressTunnels,\n") {
		t.Error("the bypass path does not use the departure-aware tunnels")
	}
	i := strings.Index(src, "localDialer := edgeplane.ConnectorEgressDialer{")
	if i < 0 {
		t.Fatal("the mesh ingress dialer is not where this test looks for it")
	}
	ingress := src[i : i+800]
	if !strings.Contains(ingress, "Tunnels:        tunnelManager,") {
		t.Error("the mesh ingress dialer was given the departure-aware tunnels; it cannot relay onward, so it must refuse at once")
	}
	for _, wiring := range []string{
		"connectorDepartures.arrived(connectorID)",
		"connectorDepartures.departed(connectorID)",
		"hurry: connectorDepartures.hurryRequests(), pulled: connectorDepartures.announce,",
	} {
		if !strings.Contains(src, wiring) {
			t.Errorf("not wired: %s", wiring)
		}
	}
}

// ★ THE DECRYPTED PATH WAITS THE SAME WAY. A flow the Edge inspects reaches a connector through its own dial,
// and refusing it there while the bypass path waits would leave the fix half applied.
func TestTheInspectedPathAlsoWaitsForAConnectorThatJustLeft(t *testing.T) {
	departures := newConnectorDepartureLog(5*time.Second, 0)
	reg, dialer, _ := departedConnectorScene(t, departures)
	departures.departed("conn-home")
	dial := edgeplane.ConnectorEgressDialContextWithCandidates(nil, dialer.ResolveConnector, nil, dialer.Tunnels,
		"tenant-a", "region-b", nil, dialer.PeerEdges, nil)

	go func() {
		time.Sleep(100 * time.Millisecond)
		if _, err := reg.RecordAttachedRegion("tenant-a", "conn-home", "region-a"); err != nil {
			t.Errorf("record where it went: %v", err)
		}
		departures.learned("conn-home")
	}()
	conn, err := dial(context.Background(), "tcp", "app.corp.internal:443")
	if err != nil {
		t.Fatalf("an inspected flow for a connector that was moving between Regions was refused: %v", err)
	}
	conn.Close()
}

// ★★★ A HELD FLOW IS A NEW CONNECTION, DECIDED ON WHAT IS TRUE WHEN IT IS MADE (review of 2026-11-07, R1 and
// R2). The first version carried a flow on the candidates it knew before the wait when the route had been
// withdrawn meanwhile, and on the residency boundary it read before the wait when that had been narrowed. Both
// paths, both changes.
func TestAFlowHeldForAMoveIsRefusedWhenTheRouteOrTheBoundaryChangedMeanwhile(t *testing.T) {
	type change struct {
		name   string
		during func(reg *connector.Registry, allowed *[]string)
		said   string
	}
	changes := []change{
		{"the route was withdrawn", func(reg *connector.Registry, _ *[]string) {
			if _, err := reg.RemoveForTenant("tenant-a", "conn-home"); err != nil {
				t.Errorf("withdraw: %v", err)
			}
		}, "withdrawn"},
		{"the boundary no longer admits where the connector went", func(reg *connector.Registry, allowed *[]string) {
			if _, err := reg.RecordAttachedRegion("tenant-a", "conn-home", "region-a"); err != nil {
				t.Errorf("record where it went: %v", err)
			}
			*allowed = []string{"region-b"}
		}, "residency"},
	}
	for _, c := range changes {
		for _, path := range []string{"bypass", "inspected"} {
			t.Run(c.name+" on the "+path+" path", func(t *testing.T) {
				departures := newConnectorDepartureLog(5*time.Second, 0)
				reg, dialer, direct := departedConnectorScene(t, departures)
				allowed := []string{"region-a", "region-b"}
				var boundary sync.Mutex
				dialer.Residency = func(string) ([]string, error) { boundary.Lock(); defer boundary.Unlock(); return allowed, nil }
				departures.departed("conn-home")
				go func() {
					time.Sleep(100 * time.Millisecond)
					boundary.Lock()
					c.during(reg, &allowed)
					boundary.Unlock()
					departures.learned("conn-home")
				}()
				var err error
				started := time.Now()
				if path == "bypass" {
					_, err = openCorpHost(dialer)
				} else {
					dial := edgeplane.ConnectorEgressDialContextWithCandidates(nil, dialer.ResolveConnector, nil, dialer.Tunnels,
						"tenant-a", "region-b", dialer.Residency, dialer.PeerEdges, nil)
					_, err = dial(context.Background(), "tcp", "app.corp.internal:443")
				}
				if err == nil {
					t.Fatal("a flow held for a move was carried on what was true before the wait")
				}
				if !strings.Contains(err.Error(), c.said) {
					t.Fatalf("the refusal does not say why: %v", err)
				}
				if waited := time.Since(started); waited > 3*time.Second {
					t.Fatalf("the refusal came after %s; it should come as soon as the change is known", waited)
				}
				if direct.called {
					t.Fatal("a destination a connector fronted was dialled directly")
				}
			})
		}
	}
}

// ★ AND A LOOKUP THAT CANNOT BE MADE AFTER THE WAIT IS A REFUSAL, not a reason to keep the old answer.
func TestAFlowHeldForAMoveIsRefusedWhenTheRouteCannotBeLookedUpAgain(t *testing.T) {
	departures := newConnectorDepartureLog(5*time.Second, 0)
	_, dialer, _ := departedConnectorScene(t, departures)
	first := true
	underlying := dialer.ResolveConnector
	dialer.ResolveConnector = func(ctx context.Context, tenant, destination, ns string) (model.ConnectorRegistration, bool, error) {
		if first {
			first = false
			return underlying(ctx, tenant, destination, ns)
		}
		return model.ConnectorRegistration{}, false, errors.New("the catalogue is unreadable")
	}
	departures.departed("conn-home")
	go func() { time.Sleep(100 * time.Millisecond); departures.learned("conn-home") }()
	_, err := openCorpHost(dialer)
	if err == nil || !strings.Contains(err.Error(), "could not be looked up again") {
		t.Fatalf("a flow whose route could not be looked up again was not refused for that: %v", err)
	}
}
