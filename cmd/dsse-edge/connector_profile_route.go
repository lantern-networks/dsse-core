package main

// connector_profile_route.go — the durable half of a connector's configuration, re-fetched rather than
// enrolled with.
//
// ★★★ A TOKEN IS ONE-TIME AND SHORT-LIVED; CONFIGURATION IS DURABLE AND CHANGES (the operator's framing,
// 2026-08-26). A device has both: a one-time enrolment token, and a PROFILE that carries every region and is
// fetched again whenever the deployment's answer moves. A connector had only the token — so the doors it may
// use were whatever was true on the day somebody pressed "Add connector", frozen into its state directory.
//
// Add a region to the deployment and every connector already in the field keeps a door list that does not
// contain it: the new region can never be failed over to, and the only way to change that is to enrol the
// connector again. That is the same defect win-dev-1 argued against for the endpoint's IPv6 flag in letter
// 107 — a fact baked at issue time that the world then moves away from.
//
// So the token keeps the BOOTSTRAP half — enough to make the first connection when the region it names is the
// one that is away — and this carries the durable half, on the poll the connector already runs.
//
// ★ IT IS NOT FOLDED INTO effective-routes. That answer is the connector's SSRF allowlist: what it may dial
// inside the customer's network. Which doors it may use to reach this deployment is a different question with
// a different blast radius, and a screen or a log that conflates them cannot say which one changed.

import (
	"net/http"
	"strings"
)

// connectorProfile is what a connector re-reads to stay configured.
type connectorProfile struct {
	SchemaVersion string `json:"schema_version"`
	TenantID      string `json:"tenant_id"`
	Site          string `json:"site,omitempty"`
	// EdgeEndpoints is every door this deployment answers on, in the operator's order, as "region=URL".
	EdgeEndpoints []string `json:"edge_endpoints"`
	Note          string   `json:"note"`
}

// connectorProfileFor builds the answer. regions is read LIVE so a region added after this node started
// appears in the next poll without restarting it — the same rule the agent profile follows.
// ★ AND THE ORGANIZATION IS NAMED HERE TOO (2026-08-29). Same defect as the agent profile, in the artefact a
// CONNECTOR takes: the tenant was in hand and the region list was asked for without it, so a customer pinned
// to one region was handed doors in the other.
func connectorProfileFor(tenantID, site, fallbackEdgeURL string, regions func(tenantID string) []regionEndpoint) connectorProfile {
	endpoints := agentProfileEndpoints(fallbackEdgeURL, tenantID, regions)
	return connectorProfile{
		SchemaVersion: "connector_profile.v1",
		TenantID:      strings.TrimSpace(tenantID),
		Site:          strings.TrimSpace(site),
		EdgeEndpoints: endpoints,
		Note:          connectorProfileNote(endpoints),
	}
}

// connectorProfileNote says what the list means for the estate behind this connector, because the number on
// its own does not: one door is a deployment that cannot fail over, and a connector reading this is the
// party that finds out first.
func connectorProfileNote(endpoints []string) string {
	switch len(endpoints) {
	case 0:
		return "this deployment has not been told any address a connector can reach it on, so this connector " +
			"has nothing to fail over to and nothing to reconnect to if its current door stops answering"
	case 1:
		return "one door: if the region it leads to stops answering, everything behind this connector is " +
			"unreachable until it comes back"
	default:
		return "tried in this order; a connector that loses one door moves to the next, so the estate behind " +
			"it survives losing a region"
	}
}

func registerConnectorProfileRoute(mux *http.ServeMux, authorize func(http.ResponseWriter, *http.Request, string) bool,
	tenantID string, fallbackEdgeURL string, regions func(tenantID string) []regionEndpoint, siteOf func(connectorID string) string) {
	mux.HandleFunc("GET /connectors/{connector_id}/profile", func(w http.ResponseWriter, r *http.Request) {
		cid := r.PathValue("connector_id")
		if !authorize(w, r, cid) {
			return
		}
		site := ""
		if siteOf != nil {
			site = siteOf(cid)
		}
		writeJSON(w, http.StatusOK, connectorProfileFor(tenantID, site, fallbackEdgeURL, regions))
	})
}
