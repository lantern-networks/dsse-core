package edgeplane

import (
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// ★★★ THE CATALOG'S REGION IS WHERE THE CONNECTOR STARTED, NOT WHERE IT IS.
//
// A connector is given several doors so it survives losing a region. When it fails over, its registration —
// written once, at first registration — still names the region it left. Every Edge then meshes to that region,
// the far side answers "no live tunnel", and everything behind the connector is unreachable while the connector
// itself is healthy and attached one hop away. These tests hold the one thing a node can always know for
// itself: it is holding the tunnel.

type fakeConnectorTunnels map[string]*tunnel.Session

func (f fakeConnectorTunnels) Get(connectorID string) (*tunnel.Session, bool) {
	s, ok := f[connectorID]
	return s, ok
}

type fakePeerEdges map[string]*tunnel.Session

func (f fakePeerEdges) PeerEdgeFor(region string) (*tunnel.Session, bool) {
	s, ok := f[region]
	return s, ok
}

func alwaysMeshEligible(string) bool { return true }

func TestConnectorHeldHereIsLocalEvenWhenTheCatalogSaysAnotherRegion(t *testing.T) {
	here := &tunnel.Session{}
	peer := &tunnel.Session{}
	conn := model.ConnectorRegistration{ID: "conn-1", EdgeRegionID: "region-b"}

	// Control: the SAME catalog entry with no tunnel held here resolves across the mesh. If this stops
	// happening the test below proves nothing.
	got, err := connectorEgressSessionFor(conn, "internal.example.test:8080", "region-a", nil,
		alwaysMeshEligible, fakeConnectorTunnels{}, fakePeerEdges{"region-b": peer})
	if err != nil {
		t.Fatalf("control: expected the mesh link to region-b, got error %v", err)
	}
	if got != peer {
		t.Fatalf("control: expected the region-b peer link, got %p", got)
	}

	// The connector failed over into THIS region: the tunnel is here, so the flow is served here.
	got, err = connectorEgressSessionFor(conn, "internal.example.test:8080", "region-a", nil,
		alwaysMeshEligible, fakeConnectorTunnels{"conn-1": here}, fakePeerEdges{"region-b": peer})
	if err != nil {
		t.Fatalf("connector held here: %v", err)
	}
	if got != here {
		t.Fatalf("expected the local tunnel this node is holding, got %p (peer=%p)", got, peer)
	}
}

func TestConnectorHeldHereDoesNotEscapeTheResidencyBoundary(t *testing.T) {
	here := &tunnel.Session{}
	conn := model.ConnectorRegistration{ID: "conn-1", EdgeRegionID: "region-b"}

	// Holding the tunnel says WHERE the connector is; it does not say the tenant may occupy that region. This
	// tenant is pinned to region-b, so a region-a Edge must not start serving it just because the connector
	// moved next door — the recorded region stands and the flow fails closed, naming region-b.
	got, err := connectorEgressSessionFor(conn, "internal.example.test:8080", "region-a", []string{"region-b"},
		alwaysMeshEligible, fakeConnectorTunnels{"conn-1": here}, nil)
	if err == nil {
		t.Fatalf("a tenant pinned away from region-a must not be served here; got session %p", got)
	}
	if got == here {
		t.Fatal("the flow escaped the residency boundary through the local tunnel")
	}
	if !strings.Contains(err.Error(), "region-b") {
		t.Fatalf("the refusal should name the region the catalog still records: %v", err)
	}
}

// The substitution must leave a connector that genuinely registered HERE exactly as it was, including for a
// tenant pinned elsewhere: that case is decided by the reach rule, not by this node's tunnel table.
func TestConnectorRegisteredHereIsUnchangedByTheSubstitution(t *testing.T) {
	here := &tunnel.Session{}
	conn := model.ConnectorRegistration{ID: "conn-1", EdgeRegionID: "region-a"}

	for _, allowed := range [][]string{nil, {"region-a"}, {"region-b"}} {
		got, err := connectorEgressSessionFor(conn, "internal.example.test:8080", "region-a", allowed,
			alwaysMeshEligible, fakeConnectorTunnels{"conn-1": here}, nil)
		if err != nil {
			t.Fatalf("allowed=%v: %v", allowed, err)
		}
		if got != here {
			t.Fatalf("allowed=%v: expected the local tunnel, got %p", allowed, got)
		}
	}

	// And with no tunnel held, the same entry still reports the absence rather than inventing a session.
	if _, err := connectorEgressSessionFor(conn, "internal.example.test:8080", "region-a", nil,
		alwaysMeshEligible, fakeConnectorTunnels{}, nil); err == nil {
		t.Fatal("expected the no-live-tunnel refusal")
	}
}

// The reported region — written by whichever node terminated the connector's tunnel — beats the registered
// one, which is what the connector declared at enrolment and never moves again. Without this, a connector
// that failed over is routed to the region it left by every node that is not itself holding a tunnel to it.
func TestTheReportedRegionBeatsTheRegisteredOne(t *testing.T) {
	peerA := &tunnel.Session{}
	conn := model.ConnectorRegistration{ID: "conn-1", EdgeRegionID: "region-b", AttachedRegionID: "region-a"}

	// This Edge is in region-c, holds no tunnel, and must mesh to where the connector ACTUALLY is.
	got, err := connectorEgressSessionFor(conn, "internal.example.test:8080", "region-c", nil,
		alwaysMeshEligible, fakeConnectorTunnels{}, fakePeerEdges{"region-a": peerA})
	if err != nil {
		t.Fatalf("expected the mesh link to region-a, where the connector was last seen: %v", err)
	}
	if got != peerA {
		t.Fatalf("expected the region-a peer link, got %p", got)
	}

	// And a node in the region the connector LEFT must not treat it as local just because the registration
	// still names that region — it holds no tunnel, and the flow has somewhere real to go.
	got, err = connectorEgressSessionFor(conn, "internal.example.test:8080", "region-b", nil,
		alwaysMeshEligible, fakeConnectorTunnels{}, fakePeerEdges{"region-a": peerA})
	if err != nil {
		t.Fatalf("the region it left must relay to where it went: %v", err)
	}
	if got != peerA {
		t.Fatalf("expected the region-a peer link from the abandoned region, got %p", got)
	}

	// With nothing reported, the registration is all there is and behaviour is unchanged.
	unreported := model.ConnectorRegistration{ID: "conn-1", EdgeRegionID: "region-b"}
	if _, err := connectorEgressSessionFor(unreported, "internal.example.test:8080", "region-c", nil,
		alwaysMeshEligible, fakeConnectorTunnels{}, fakePeerEdges{"region-a": peerA}); err == nil {
		t.Fatal("with no report, region-b is where it is said to be, and there is no link to region-b here")
	}
}

// ★★★ A DECISION THAT REPORTS A DIFFERENT INPUT THAN IT USED IS WORSE THAN NO LINE AT ALL. These lines exist
// so a relayed or refused flow says why. Measured on a real failover: a node that had CORRECTLY relayed to
// region-a printed connector_region="region-b" — the registered field — which reads exactly like the defect
// it was proving fixed.
func TestTheDecisionLineNamesTheRegionItActuallyUsed(t *testing.T) {
	moved := model.ConnectorRegistration{ID: "conn-1", EdgeRegionID: "region-b", AttachedRegionID: "region-a"}
	if got := connectorRegionForDecision(moved); got != "region-a" {
		t.Fatalf("the decision uses where it was last seen: %q", got)
	}
	got := ConnectorRegionForLog(moved)
	if !strings.Contains(got, "region-a") {
		t.Fatalf("the line must name the region the decision used: %q", got)
	}
	if !strings.Contains(got, "registered in region-b") {
		t.Fatalf("and where it registered, because the difference is the fact worth reading: %q", got)
	}

	// Where they agree, saying it twice is noise.
	settled := model.ConnectorRegistration{ID: "conn-1", EdgeRegionID: "region-b", AttachedRegionID: "region-b"}
	if got := ConnectorRegionForLog(settled); got != "region-b" {
		t.Fatalf("a connector where it registered needs no parenthesis: %q", got)
	}
	unreported := model.ConnectorRegistration{ID: "conn-1", EdgeRegionID: "region-b"}
	if got := ConnectorRegionForLog(unreported); got != "region-b" {
		t.Fatalf("nothing reported means the registration is all there is: %q", got)
	}
	nowhere := model.ConnectorRegistration{ID: "conn-1", AttachedRegionID: "region-a"}
	if got := ConnectorRegionForLog(nowhere); got != "region-a" {
		t.Fatalf("a connector with no registered region still names where it is: %q", got)
	}
}
