package edgeplane

import "strings"

// ReachDisposition is how a steered flow reaches the connector that fronts its destination, once the connector's
// REGION is taken into account (the multi-region extension of the route layer — see
// docs/multi_region_edge_architecture_design.md). It is proprietary: the single-region route layer (OSS) is
// region-agnostic; this is the region dimension on top.
type ReachDisposition int

const (
	// ReachLocal: the connector terminates in THIS edge's region -> relay through the local connector tunnel
	// (the single-region path already built). An unset/empty connector region is treated as local so a
	// single-region deployment is unaffected.
	ReachLocal ReachDisposition = iota
	// ReachHairpin: the connector is in another region within the tenant's residency boundary, and the app is NOT
	// mesh-opted-in -> the flow is served by that region's edge (a steering decision; decryption stays in the
	// app's region — the residency-clean default).
	ReachHairpin
	// ReachMesh: same as hairpin but the app opted into inter-region mesh -> keep the user on this edge and relay
	// to the connector's region edge (decryption happens here, in-boundary).
	ReachMesh
	// ReachDenyOutOfBoundary: the connector's region is NOT in the tenant's allowed regions -> fail closed.
	// Residency beats availability; a misconfigured catalog can never route a tenant out of its boundary.
	ReachDenyOutOfBoundary
)

type reachDecision struct {
	Disposition ReachDisposition
	Region      string // the connector's region (for hairpin/mesh targeting / logging)
}

// ResolveConnectorReach decides how a flow reaches a connector, given the connector's region, THIS edge's region,
// the tenant's allowed regions, and whether the destination app opted into inter-region mesh. It is a pure
// function — the data-path execution (hairpin steering / mesh relay) is separate.
//
//   - empty connector region, or a match to the local region -> ReachLocal (single-region safe).
//   - remote region NOT in a non-empty allowedRegions -> ReachDenyOutOfBoundary (residency).
//   - remote region in-boundary -> ReachMesh if the app opted in, else ReachHairpin.
//
// An empty allowedRegions means "no residency restriction" (an unpinned tenant ranges over all regions,), so
// it does not by itself deny a remote region.
func ResolveConnectorReach(connectorRegion, localRegion string, allowedRegions []string, meshEligible bool) reachDecision {
	cr := strings.TrimSpace(connectorRegion)
	lr := strings.TrimSpace(localRegion)
	if cr == "" || strings.EqualFold(cr, lr) {
		return reachDecision{Disposition: ReachLocal, Region: lr}
	}
	if len(allowedRegions) > 0 && !ContainsRegionFold(allowedRegions, cr) {
		return reachDecision{Disposition: ReachDenyOutOfBoundary, Region: cr}
	}
	if meshEligible {
		return reachDecision{Disposition: ReachMesh, Region: cr}
	}
	return reachDecision{Disposition: ReachHairpin, Region: cr}
}

func ContainsRegionFold(regions []string, region string) bool {
	for _, r := range regions {
		if strings.EqualFold(strings.TrimSpace(r), strings.TrimSpace(region)) {
			return true
		}
	}
	return false
}
