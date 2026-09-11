package main

// a_connector_is_given_every_door.go — the enrolment token carries the deployment's whole region map.
//
// ★★★ THE SUPPORTED WAY TO INSTALL A CONNECTOR PRODUCED ONE THAT CANNOT FAIL OVER (2026-08-26). The token the
// Console's "Add connector" hands out carries a single edge_url. A connector built from it therefore has ONE
// door: when that region stops answering, everything behind that connector is unreachable until a human
// edits its command line. Region failover was implemented, measured, and unreachable through the only path a
// customer is given — every measurement of it this week was made with --edge-endpoints passed BY HAND.
//
// A device gets the whole map: the agent profile carries every region, read live so a region added later
// appears without restarting the node that issues profiles. A connector dials the same agent plane and has
// the same reason to know every door, so it is given the same list from the same place.
//
// ★ THE SINGLE URL STAYS IN THE TOKEN. A connector too old to read the list still finds what it always read,
// and an operator who deliberately pins one door is not overridden.

import "strings"

// connectorEnrollmentRegions answers the deployment's region map for the token minter.
//
// Package-level for the same reason connectorCPReport is: the handler that needs it is built in a different
// function from the one that can construct it, and the map has to be read LIVE — a region added after this
// node started must appear in the next token without restarting it.
var connectorEnrollmentRegions func(tenantID string) []regionEndpoint

// connectorEnrollmentEndpointList renders the doors a connector should try, in the operator's order, as the
// "region=URL;region=URL" the connector already parses. Empty when this node knows of no regions, in which
// case the token's single edge_url is all there is — which is what a single-region deployment has anyway.
func connectorEnrollmentEndpointList(tenantID string) string {
	if connectorEnrollmentRegions == nil {
		return ""
	}
	parts := []string{}
	for _, e := range connectorEnrollmentRegions(tenantID) {
		region, endpoint := strings.TrimSpace(e.Region), strings.TrimSpace(e.Endpoint)
		if region == "" || endpoint == "" {
			continue
		}
		parts = append(parts, region+"="+endpoint)
	}
	if len(parts) < 2 {
		// One door is not a list, and writing it as one would say this connector can fail over when it cannot.
		return ""
	}
	return strings.Join(parts, ";")
}
