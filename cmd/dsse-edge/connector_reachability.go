package main

import (
	"context"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tunnel"
)

// Connector UX Slice 3: reachability diagnostics. The edge asks the connector that fronts an application to
// probe the application's OWN destination (DNS/TCP/TLS/HTTP) over the tunnel, then layers a POLICY SIMULATION
// (a pure decision dry-run) on top. It flows NO real user traffic: the probe is bounded and body-less, and the
// policy step calls the evaluator directly without proxying, logging a decision, or touching any store. The
// connector independently confirms the destination is within its reachable_routes (SSRF guard), so reachability
// is always scoped to what the connector already fronts.

const reachabilitySchemaVersion = "application_reachability.v1"

// reachabilityStatus is the top-level outcome of a reachability test.
const (
	reachabilityStatusOK          = "ok"           // a probe ran (reachable or not — see failure_layer)
	reachabilityStatusNoConnector = "no_connector" // no connected connector fronts the app (lab: 0 connectors)
	reachabilityStatusNoTunnel    = "no_tunnel"    // connector registered but its tunnel is not connected
	reachabilityStatusProbeFailed = "probe_failed" // the tunnel round-trip itself failed (transport error)
)

// reachabilityResult is the secret-safe response. The destination host / resolved IPs ARE returned because the
// caller holds admin.applications.read (the permission gate for private destinations); the AUDIT record, by
// contrast, stores only presence + verdict, never the host or IPs.
type reachabilityResult struct {
	SchemaVersion    string                 `json:"schema_version"`
	ApplicationID    string                 `json:"application_id"`
	Status           string                 `json:"status"`
	Reachable        bool                   `json:"reachable"`
	FailureLayer     string                 `json:"failure_layer,omitempty"`
	SuggestedAction  string                 `json:"suggested_action,omitempty"`
	Connector        *reachabilityConnector `json:"connector,omitempty"`
	Destination      reachabilityTarget     `json:"destination"`
	Probe            *tunnel.ProbeResult    `json:"probe,omitempty"`
	PolicySimulation map[string]any         `json:"policy_simulation"`
	// RouteError is a ROUTE-LEVEL error that is distinct from the policy decision (Connector UX Slice 6). The
	// only kind today is "residency": the fronting connector's region is outside the tenant's residency boundary,
	// so the route is unusable for a residency reason — surfaced separately from a policy denial so an operator can
	// tell "blocked by policy" from "structurally unreachable across the residency boundary". Omitted when none.
	RouteError *reachabilityRouteError `json:"route_error,omitempty"`
}

// reachabilityRouteError is a non-policy reason a route cannot carry traffic. It is intentionally separate from
// PolicySimulation: a residency block is a property of WHERE the connector lives, not of WHO is authorized.
type reachabilityRouteError struct {
	Kind            string   `json:"kind"` // "residency"
	ConnectorRegion string   `json:"connector_region,omitempty"`
	ServingRegion   string   `json:"serving_region,omitempty"`
	AllowedRegions  []string `json:"allowed_regions,omitempty"`
	Message         string   `json:"message"`
}

type reachabilityConnector struct {
	ConnectorID      string `json:"connector_id"`
	Name             string `json:"name,omitempty"`
	ConnectorGroupID string `json:"connector_group_id,omitempty"`
	EdgeRegionID     string `json:"edge_region_id,omitempty"`
	TunnelConnected  bool   `json:"tunnel_connected"`
}

type reachabilityTarget struct {
	Host          string `json:"host,omitempty"`
	Port          int    `json:"port,omitempty"`
	ProbeProtocol string `json:"probe_protocol,omitempty"`
}

// reachabilityProbeProtocolFor maps the route's service family to the probe depth: web families do the full
// DNS+TCP+TLS+HTTP stack; everything else (ssh/database/rdp/tcp/...) is a TCP reachability check.
func reachabilityProbeProtocolFor(serviceFamily string) string {
	switch serviceFamily {
	case "https", "http", "web", "saas":
		return tunnel.ProbeProtocolWeb
	default:
		return tunnel.ProbeProtocolTCP
	}
}

// reachabilityPolicySimulation runs a PURE policy dry-run for the app route. evaluator.Evaluate has no side
// effects (no proxy, no logging, no store write), so this answers "would policy allow this flow?" without
// flowing any traffic. It also reports the publish-review assignment counts for the operator.
func reachabilityPolicySimulation(evaluator decision.Evaluator, tenantID, applicationID, connectorID string, profile edgeplane.ApplicationRouteProfile) map[string]any {
	req := model.DecisionRequest{
		TenantID:               tenantID,
		ApplicationID:          applicationID,
		ApplicationSensitivity: profile.ApplicationSensitivity,
		ConnectorID:            connectorID,
		Destination:            profile.Destination,
		DestinationPort:        profile.DestinationPort,
		Protocol:               profile.Protocol,
		FQDN:                   profile.Destination,
		SNI:                    profile.Destination,
		ServiceFamily:          profile.ServiceFamily,
		ConnectionInitiator:    "client",
		SourceRole:             "managed_endpoint",
		DestinationRole:        profile.DestinationRole,
	}
	dec := evaluator.Evaluate(req)
	policyAssigned, usersAllowedNow := applicationPolicyAssignment(applicationID, evaluator)
	return map[string]any{
		"evaluated":         true,
		"dry_run":           true,
		"decision":          dec.Decision,
		"permitted":         decisionPermitsConnectorRoute(dec.Decision),
		"reason_codes":      dec.ReasonCodes,
		"policy_assigned":   policyAssigned,
		"users_allowed_now": usersAllowedNow,
	}
}

// reachabilityProbeFrame builds the bounded probe request for the app's route.
func reachabilityProbeFrame(requestID string, profile edgeplane.ApplicationRouteProfile) tunnel.Frame {
	return tunnel.Frame{
		Type:                 tunnel.FrameProbeRequest,
		RequestID:            requestID,
		Host:                 profile.Destination,
		Port:                 profile.DestinationPort,
		ProbeProtocol:        reachabilityProbeProtocolFor(profile.ServiceFamily),
		ConnectTimeoutMillis: tunnel.DefaultProbeTimeoutMillis,
	}
}

// reachabilitySuggestedAction maps the failing layer (or top-level status) to an operator-facing hint.
func reachabilitySuggestedAction(status, failureLayer string) string {
	switch status {
	case reachabilityStatusNoConnector:
		return "No connected connector fronts this application. Enroll or connect a connector in its site."
	case reachabilityStatusNoTunnel:
		return "The connector is registered but its tunnel is not connected. Check connector health and heartbeat."
	case reachabilityStatusProbeFailed:
		return "The reachability probe could not complete over the connector tunnel. Retry or check connector health."
	}
	switch failureLayer {
	case tunnel.ProbeFailureLayerRoute:
		return "Destination is outside the connector's reachable routes. Add it to the connector reachable_routes or pick a connector that fronts it."
	case tunnel.ProbeFailureLayerDNS:
		return "Check the internal DNS resolver for the connector site."
	case tunnel.ProbeFailureLayerTCP:
		return "Check that the destination is listening and the connector-site firewall allows the port."
	case tunnel.ProbeFailureLayerTLS:
		return "Check the destination TLS listener and certificate."
	case tunnel.ProbeFailureLayerHTTP:
		return "TCP/TLS reached the destination but the HTTP request failed. Check the web service."
	default:
		return ""
	}
}

// evaluateReachabilityResidency reports a ROUTE-LEVEL residency error (Slice 6) when the fronting connector's
// region falls outside the tenant's residency boundary — the same edgeplane.ReachDenyOutOfBoundary decision the live egress
// dialer fails closed on (connector_egress_dialer.go), so the diagnostic matches runtime behaviour. It is NOT a
// policy decision: it is returned separately so the operator can distinguish "denied by policy" from "unreachable
// across the residency boundary". Returns nil for the local / hairpin / mesh-eligible / in-boundary cases.
func evaluateReachabilityResidency(connectorRegion, localRegion string, allowedRegions []string, meshEligible func(host string) bool, destination string) *reachabilityRouteError {
	mesh := meshEligible != nil && meshEligible(destination)
	dec := edgeplane.ResolveConnectorReach(connectorRegion, localRegion, allowedRegions, mesh)
	if dec.Disposition != edgeplane.ReachDenyOutOfBoundary {
		return nil
	}
	return &reachabilityRouteError{
		Kind:            "residency",
		ConnectorRegion: dec.Region,
		ServingRegion:   localRegion,
		AllowedRegions:  append([]string(nil), allowedRegions...),
		Message:         "The connector that fronts this destination is in a region outside the tenant's residency boundary; this route is unavailable for residency reasons (separate from any policy decision).",
	}
}

// reachabilityProber abstracts the tunnel round-trip so the result builder is testable without a live tunnel.
type reachabilityProber func(ctx context.Context, frame tunnel.Frame) (tunnel.Frame, error)

// buildReachabilityResult is the pure (tunnel-injected) core of the handler: resolve the connector + route,
// probe via the injected prober, and layer the policy dry-run. tunnelConnected=false short-circuits to a
// no_tunnel result (fail-closed) but STILL returns the policy simulation so the operator sees authorization
// state even when reachability cannot be tested.
func buildReachabilityResult(ctx context.Context, evaluator decision.Evaluator, tenantID, applicationID string, conn model.ConnectorRegistration, connectorFound bool, tunnelConnected bool, profile edgeplane.ApplicationRouteProfile, prober reachabilityProber) reachabilityResult {
	result := reachabilityResult{
		SchemaVersion: reachabilitySchemaVersion,
		ApplicationID: applicationID,
		Destination: reachabilityTarget{
			Host:          profile.Destination,
			Port:          profile.DestinationPort,
			ProbeProtocol: reachabilityProbeProtocolFor(profile.ServiceFamily),
		},
		PolicySimulation: reachabilityPolicySimulation(evaluator, tenantID, applicationID, conn.ID, profile),
	}

	if !connectorFound {
		result.Status = reachabilityStatusNoConnector
		result.SuggestedAction = reachabilitySuggestedAction(reachabilityStatusNoConnector, "")
		return result
	}

	result.Connector = &reachabilityConnector{
		ConnectorID:      conn.ID,
		Name:             conn.Name,
		ConnectorGroupID: conn.ConnectorGroupID,
		EdgeRegionID:     conn.EdgeRegionID,
		TunnelConnected:  tunnelConnected,
	}

	if !tunnelConnected || prober == nil {
		result.Status = reachabilityStatusNoTunnel
		result.SuggestedAction = reachabilitySuggestedAction(reachabilityStatusNoTunnel, "")
		return result
	}

	frame := reachabilityProbeFrame(randomEdgeID("probe_", time.Now().UTC()), profile)
	frame.TenantID = tenantID
	frame.ProbeConnectorID = conn.ID
	response, err := prober(ctx, frame)
	if response.Probe == nil {
		// transport error / timeout with no result payload.
		result.Status = reachabilityStatusProbeFailed
		result.SuggestedAction = reachabilitySuggestedAction(reachabilityStatusProbeFailed, "")
		if err != nil {
			result.FailureLayer = ""
		}
		return result
	}
	result.Status = reachabilityStatusOK
	result.Probe = response.Probe
	result.Reachable = response.Probe.Reachable
	result.FailureLayer = response.Probe.FailureLayer
	if !result.Reachable {
		result.SuggestedAction = reachabilitySuggestedAction(reachabilityStatusOK, response.Probe.FailureLayer)
	}
	return result
}

// reachabilityAuditDetails is the SECRET-SAFE audit projection: it records the verdict and which layer failed,
// plus presence booleans — never the destination host, resolved IPs, certificate fields, or HTTP status.
func reachabilityAuditDetails(applicationID string, result reachabilityResult) map[string]any {
	details := map[string]any{
		"application_id":         applicationID,
		"reachability_status":    result.Status,
		"reachable":              result.Reachable,
		"failure_layer":          result.FailureLayer,
		"destination_present":    result.Destination.Host != "",
		"probe_protocol":         result.Destination.ProbeProtocol,
		"tunnel_connected":       result.Connector != nil && result.Connector.TunnelConnected,
		"policy_simulation_only": true,
		"residency_route_error":  result.RouteError != nil,
		"reason_codes":           []string{"connector_reachability_diagnostic"},
	}
	if sim := result.PolicySimulation; sim != nil {
		details["policy_decision"] = sim["decision"]
		details["policy_permitted"] = sim["permitted"]
	}
	return details
}
