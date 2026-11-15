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

// AuthOwner is the kernel-attributed OS principal and login incarnation, reported
// by the privileged device agent over mTLS. Neither is read from HTTP headers.
type AuthOwner struct{ Principal, Session string }
type authOwnerContextKey struct{}

func WithAuthOwner(ctx context.Context, owner AuthOwner) context.Context {
	return context.WithValue(ctx, authOwnerContextKey{}, owner)
}
func AuthOwnerFromContext(ctx context.Context) AuthOwner {
	o, _ := ctx.Value(authOwnerContextKey{}).(AuthOwner)
	return o
}

// TransportServerName identifies the OUTER device-to-Edge TLS entrance. It is
// set by the authenticated HTTP transport, never a header or application SNI.
type transportServerNameContextKey struct{}

func WithTransportServerName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, transportServerNameContextKey{}, strings.ToLower(strings.TrimSpace(name)))
}
func TransportServerNameFromContext(ctx context.Context) string {
	name, _ := ctx.Value(transportServerNameContextKey{}).(string)
	return name
}

// WithConnectorAccessAtOpen records that the flow a decrypted request was read out of was decided by Connector
// Access when it opened, and let through.
//
// A flow to a registered network is Connector Access, and what is inside it is too. The handler on the far
// side of decryption builds a fresh decision request for every HTTP request, and without this it could not
// know which plane the connection belonged to: it asked the Internet Access rules, so one visit to a private
// application was decided twice, by two planes, and its access-log rows named an Internet Access rule.
func WithConnectorAccessAtOpen(ctx context.Context) context.Context {
	return WithConnectorAccessAtOpenAfterSignIn(ctx, "")
}

// WithConnectorAccessAtOpenAfterSignIn is WithConnectorAccessAtOpen for a flow that was let through only after
// the sign-in a rule asks for was completed; signInDoneForRule is that rule's id.
func WithConnectorAccessAtOpenAfterSignIn(ctx context.Context, signInDoneForRule string) context.Context {
	return context.WithValue(ctx, connectorAccessAtOpenContextKey{}, connectorAccessAtOpen{signInDoneForRule: strings.TrimSpace(signInDoneForRule)})
}

// ConnectorAccessAtOpenFromContext reports whether WithConnectorAccessAtOpen marked this request's flow.
func ConnectorAccessAtOpenFromContext(ctx context.Context) bool {
	_, ok := ctx.Value(connectorAccessAtOpenContextKey{}).(connectorAccessAtOpen)
	return ok
}

// ConnectorSignInDoneForRuleFromContext is the rule whose sign-in the flow completed before it opened, or "".
func ConnectorSignInDoneForRuleFromContext(ctx context.Context) string {
	v, _ := ctx.Value(connectorAccessAtOpenContextKey{}).(connectorAccessAtOpen)
	return v.signInDoneForRule
}

type connectorAccessAtOpen struct{ signInDoneForRule string }

type connectorAccessAtOpenContextKey struct{}
