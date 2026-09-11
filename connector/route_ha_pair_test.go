package connector

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func fronting(id, region string, domains ...string) model.ConnectorRegistration {
	return model.ConnectorRegistration{
		ID: id, EdgeRegionID: region,
		ReachableRoutes: model.ConnectorReachableRoutes{FQDNDomains: domains},
	}
}

// ★★★ A SITE HOLDS MORE THAN ONE CONNECTOR ON PURPOSE (the operator's reminder, 2026-08-26). Bindings are
// authored on the SITE, so an HA pair fronts the same names. Resolving to one of them and stopping hands every
// flow to the same member and fails outright when that member is the one an Edge cannot reach — while its
// partner sits live holding the identical route.
func TestBothMembersOfAnHAPairAreOffered(t *testing.T) {
	pair := []model.ConnectorRegistration{
		fronting("conn-b", "region-b", "internal.example.test"),
		fronting("conn-a", "region-a", "internal.example.test"),
	}
	got := ResolveConnectorsForHost("internal.example.test", pair)
	if len(got) != 2 {
		t.Fatalf("an HA pair produced %d candidate(s): %v", len(got), got)
	}
	// Stable within a specificity, so routing does not flap between members request by request.
	if got[0] != "conn-a" || got[1] != "conn-b" {
		t.Fatalf("the order is not stable by id: %v", got)
	}
	// And the single-winner form still answers the same first choice, so nothing that has not been changed
	// starts behaving differently.
	if id, ok := ResolveConnectorForHost("internal.example.test", pair); !ok || id != got[0] {
		t.Fatalf("the single-answer form disagrees with the candidate list: %q vs %v", id, got)
	}
}

// ★ SPECIFICITY STILL WINS OVER HA. A connector fronting the exact name comes before one fronting the parent
// domain, whichever site they are in.
func TestAMoreSpecificRouteComesFirst(t *testing.T) {
	got := ResolveConnectorsForHost("app.tokyo.corp", []model.ConnectorRegistration{
		fronting("conn-broad", "region-a", "corp"),
		fronting("conn-exact", "region-b", "app.tokyo.corp"),
		fronting("conn-mid", "region-a", "tokyo.corp"),
	})
	want := []string{"conn-exact", "conn-mid", "conn-broad"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("candidates %v; want %v", got, want)
		}
	}
}

// A host nothing fronts produces nothing — fail-closed, unchanged.
func TestAHostNoConnectorFrontsProducesNoCandidates(t *testing.T) {
	if got := ResolveConnectorsForHost("example.com", []model.ConnectorRegistration{
		fronting("conn-a", "region-a", "internal.example.test"),
	}); len(got) != 0 {
		t.Fatalf("a public host produced candidates: %v", got)
	}
}
