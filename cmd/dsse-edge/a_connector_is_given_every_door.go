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

import (
	"fmt"
	"strings"
)

// connectorEnrollmentRegions answers the deployment's region map for the token minter.
//
// Package-level for the same reason connectorCPReport is: the handler that needs it is built in a different
// function from the one that can construct it, and the map has to be read LIVE — a region added after this
// node started must appear in the next token without restarting it.
var connectorEnrollmentRegions func(tenantID string) []regionEndpoint

// connectorEnrollmentEndpointList renders the doors a connector should try, in the operator's order, as the
// "region=URL;region=URL" the connector already parses. A single permitted door is included too: the token's
// bootstrap edge_url must be checked against the same tenant-scoped list before a CSR is sent.
func connectorEnrollmentEndpointList(tenantID string) string {
	if connectorEnrollmentRegions == nil {
		return ""
	}
	return connectorEnrollmentEndpointListForRegions(connectorEnrollmentRegions(tenantID))
}

func connectorEnrollmentEndpointListForRegions(regions []regionEndpoint) string {
	parts := []string{}
	for _, e := range regions {
		region, endpoint := strings.TrimSpace(e.Region), strings.TrimSpace(e.Endpoint)
		if endpoint == "" {
			continue
		}
		if region != "" {
			parts = append(parts, region+"="+endpoint)
		} else {
			parts = append(parts, endpoint)
		}
	}
	return strings.Join(parts, ";")
}

// connectorEnrollmentMaterial chooses the first identity-enrolment door and
// the associated failover list from one snapshot of the allowed regions.
// Unlike the post-enrolment door list, this URL is used immediately for the
// certificate request. An arbitrary request or deployment fallback cannot
// override the tenant's allowed-region boundary.
func connectorEnrollmentMaterial(tenantID, requested string) (bootstrapURL, endpointList string, err error) {
	requested = strings.TrimSpace(requested)
	if connectorEnrollmentRegions == nil {
		return requested, "", nil // legacy single-region deployment without a region resolver
	}
	allowed := connectorEnrollmentRegions(tenantID)
	endpointList = connectorEnrollmentEndpointListForRegions(allowed)
	first := ""
	for _, door := range allowed {
		endpoint := strings.TrimSpace(door.Endpoint)
		if endpoint == "" {
			continue
		}
		if first == "" {
			first = endpoint
		}
		if requested != "" && strings.TrimRight(requested, "/") == strings.TrimRight(endpoint, "/") {
			return endpoint, endpointList, nil
		}
	}
	if first == "" {
		return "", "", fmt.Errorf("this tenant has no permitted Edge endpoint for connector enrollment")
	}
	if requested != "" {
		return "", "", fmt.Errorf("connector enrollment edge_url is not in this tenant's permitted Edge endpoints")
	}
	return first, endpointList, nil
}
