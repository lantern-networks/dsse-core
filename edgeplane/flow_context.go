// Per-flow identity context: the verified (T) transport device identity, the
// endpoint-reported OS user, and the source application ride the request context
// from the steer/NE layer down to the egress and auth gates. Keys are private;
// the With*/…FromContext pairs are the contract. Moved from cmd/edge (Phase 3
// step 6a, advisory).
package edgeplane

import (
	"context"
	"strings"
)

// WithTransportDevice / WithOSUser / WithSourceApp attach the per-flow identity
// values; empty strings are attached as-is (callers guard).
func WithTransportDevice(ctx context.Context, deviceIdentity string) context.Context {
	return context.WithValue(ctx, transportDeviceContextKey{}, deviceIdentity)
}

func WithOSUser(ctx context.Context, osUser string) context.Context {
	return context.WithValue(ctx, osUserContextKey{}, osUser)
}

func WithSourceApp(ctx context.Context, sourceApp string) context.Context {
	return context.WithValue(ctx, sourceAppContextKey{}, sourceApp)
}

// WithFlowTenant attaches the ORGANIZATION THIS FLOW BELONGS TO — the device's, not the node's.
//
// ★★★ THE CONNECTOR LOOKUP ON THE DECRYPTED PATH ASKED ABOUT THE NODE (2026-09-01, the fifth member of this
// family in one day, and the one that kept private access dark).
//
// A destination is matched to a connector within an organization. The steer path passes the flow's own
// organization and finds it. The intercepted path went through a proxy client built once at startup, holding
// the tenant of the policy bundle THIS EDGE pulled — the operator's, on a deployment that serves customers —
// so it found no connector for any customer's destination, fell through to the direct dialer, and was refused
// by the SSRF guard with advice to publish the destination behind a connector. It already was.
//
// The organization is a property of the FLOW, so it rides with the flow, like the device identity beside it.
func WithFlowTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, flowTenantContextKey{}, tenantID)
}

// FlowTenantFromContext is the organization this flow belongs to, or "" when nothing attached one — in which
// case the caller keeps whatever it was configured with, which is correct on a single-tenant deployment.
func FlowTenantFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(flowTenantContextKey{}).(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

type flowTenantContextKey struct{}

// transportDeviceContextKey carries the verified (T) transport device identity of a steered flow into the
// in-process decrypt-all egress request, so the gate + broker can bind a grant to the DEVICE.
type transportDeviceContextKey struct{}

func TransportDeviceFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(transportDeviceContextKey{}).(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// osUserContextKey carries the PER-FLOW logged-in OS user the endpoint agent reported (via the steer OPEN
// frame's "u=" metadata) into the in-process decrypt-all egress request. Distinct from the device: one tunnel
// (one device cert) multiplexes several users' flows on a shared machine, so the user is per-flow, not
// per-connection.
type osUserContextKey struct{}

func OSUserFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(osUserContextKey{}).(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// sourceAppContextKey carries the PER-FLOW originating app/process the endpoint agent reported (steer OPEN "a=")
// into the in-process decrypt-all egress request — the "what tool" dimension (browser vs CLI vs AI agent).
type sourceAppContextKey struct{}

func SourceAppFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(sourceAppContextKey{}).(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
