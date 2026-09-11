package edgeplane

import (
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

type meshPeersForTest map[string]*tunnel.Session

func (m meshPeersForTest) PeerEdgeFor(region string) (*tunnel.Session, bool) {
	s, ok := m[strings.ToLower(strings.TrimSpace(region))]
	return s, ok
}

// ★★★ A DEVICE THAT FAILED OVER TO ANOTHER REGION LOST ITS PRIVATE ACCESS, SILENTLY (2026-09-01, measured on
// a three-region deployment with a customer's connector in its own VPC, from both platforms independently).
//
// Cross-region reach to a connector chooses between MESH and HAIRPIN, and that choice was made solely by
// -mesh-eligible-hosts — which nothing produces. So every connector-fronted destination was hairpin, and a
// flow that crossed a region ended as "Empty reply from server" with the reason only in the Edge's log.
func TestAConnectorFrontedDestinationCrossesOnALiveMeshLink(t *testing.T) {
	conn := model.ConnectorRegistration{ID: "conn-x", EdgeRegionID: "osaka"}
	live := &tunnel.Session{}

	// No authored eligible-hosts list — which is every deployment this installer has built.
	got, err := connectorEgressSessionFor(conn, "10.60.1.176", "tokyo-east", nil, nil, nil,
		meshPeersForTest{"osaka": live})
	if err != nil {
		t.Fatalf("a destination the route layer already sends to this connector was refused: %v", err)
	}
	if got != live {
		t.Error("the flow did not take the mesh link to the connector's region")
	}
}

// ★ AND HAIRPIN REMAINS FOR THE CASE IT DESCRIBES. With no link to that region the refusal stands and names
// the region — "this deployment has no mesh" must keep meaning what it means.
func TestWithNoLinkToThatRegionTheRefusalStandsAndNamesIt(t *testing.T) {
	conn := model.ConnectorRegistration{ID: "conn-x", EdgeRegionID: "osaka"}
	_, err := connectorEgressSessionFor(conn, "10.60.1.176", "tokyo-east", nil, nil, nil,
		meshPeersForTest{"tokyo-west": &tunnel.Session{}})
	if err == nil {
		t.Fatal("a connector in a region this edge has no link to was served anyway")
	}
	if !strings.Contains(err.Error(), "osaka") {
		t.Errorf("the refusal does not name the region the connector is in: %v", err)
	}
}

// ★★ RESIDENCY BEATS AVAILABILITY, AND IS DECIDED FIRST. An organization pinned away from the connector's
// region is refused whether or not a mesh link exists — this change must not widen a boundary.
func TestResidencyStillRefusesBeforeTheMeshIsConsidered(t *testing.T) {
	conn := model.ConnectorRegistration{ID: "conn-x", EdgeRegionID: "osaka"}
	_, err := connectorEgressSessionFor(conn, "10.60.1.176", "tokyo-east", []string{"tokyo-east", "tokyo-west"},
		nil, nil, meshPeersForTest{"osaka": &tunnel.Session{}})
	if err == nil {
		t.Fatal("a connector outside the organization's residency boundary was served over the mesh")
	}
	if !strings.Contains(err.Error(), "residency") {
		t.Errorf("the refusal is not the residency one: %v", err)
	}
}
