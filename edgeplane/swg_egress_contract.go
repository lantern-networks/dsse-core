package edgeplane

import "context"

// SWG HTTP-egress contract: the in-process egress path, its headers, and the
// non-secret outcome / upstream-error-category enums shared by the egress handler,
// the NE TLS-interception forward, and the readiness endpoints. Moved from cmd/edge
// (Phase 3 step 6a, advisory). The strings are part of the logged/observed
// surface — do not rename them.

type edgeSWGNERuntimeContextKey struct{}

// WithSWGNERuntimeUsed marks the request as having traversed the NE runtime-copy
// in-process forward; SWGNERuntimeUsedFromContext reads it on the egress side.
func WithSWGNERuntimeUsed(ctx context.Context) context.Context {
	return context.WithValue(ctx, edgeSWGNERuntimeContextKey{}, true)
}

func SWGNERuntimeUsedFromContext(ctx context.Context) bool {
	used, ok := ctx.Value(edgeSWGNERuntimeContextKey{}).(bool)
	return ok && used
}

const (
	EdgeSWGHTTPEgressPath                                    = "/swg/http-egress"
	EdgeSWGHTTPEgressTargetURLHeader                         = "x-dsse-swg-target-url"
	EdgeSWGHTTPEgressNERuntimeHeader                         = "x-dsse-swg-network-extension-runtime"
	EdgeSWGEgressApplicationID                               = "app_swg_egress"
	EdgeSWGHTTPEgressRewriteEvent                            = "swg_http_egress_rewrite_recorded"
	EdgeSWGHTTPEgressReadinessSchema                         = "swg_http_egress_tls_readiness_dependency.v1"
	EdgeSWGHTTPEgressReadinessReason                         = "default_tls_decryption_required_not_observed"
	EdgeSWGHTTPEgressMacCAReason                             = "mac_ca_trust_required_not_observed"
	EdgeSWGHTTPEgressOutcomeBadRequest                       = "bad_request"
	EdgeSWGHTTPEgressOutcomeUnauthorized                     = "unauthorized"
	EdgeSWGHTTPEgressOutcomeInternalError                    = "internal_error"
	EdgeSWGHTTPEgressOutcomePolicyDenied                     = "policy_denied"
	EdgeSWGHTTPEgressOutcomeRewriteFailed                    = "rewrite_failed"
	EdgeSWGHTTPEgressOutcomeReadinessDependency              = "readiness_dependency"
	EdgeSWGHTTPEgressOutcomeUpstreamRequestFailed            = "upstream_request_failed"
	EdgeSWGHTTPEgressOutcomeUpstreamResponse                 = "upstream_response"
	EdgeSWGHTTPEgressUpstreamErrorCategoryNone               = "none"
	EdgeSWGHTTPEgressUpstreamErrorCategoryContextCanceled    = "context_canceled"
	EdgeSWGHTTPEgressUpstreamErrorCategoryTimeout            = "timeout"
	EdgeSWGHTTPEgressUpstreamErrorCategoryDNSError           = "dns_error"
	EdgeSWGHTTPEgressUpstreamErrorCategoryTCPConnectError    = "tcp_connect_error"
	EdgeSWGHTTPEgressUpstreamErrorCategoryTLSHandshakeError  = "tls_handshake_error"
	EdgeSWGHTTPEgressUpstreamErrorCategoryCertificateError   = "certificate_error"
	EdgeSWGHTTPEgressUpstreamErrorCategoryConnectionReset    = "connection_reset"
	EdgeSWGHTTPEgressUpstreamErrorCategoryConnectionRefused  = "connection_refused"
	EdgeSWGHTTPEgressUpstreamErrorCategoryNetworkUnreachable = "network_unreachable"
	EdgeSWGHTTPEgressUpstreamErrorCategoryClosedConnection   = "closed_connection"
	EdgeSWGHTTPEgressUpstreamErrorCategoryHTTP2Transport     = "http2_transport_error"
	EdgeSWGHTTPEgressUpstreamErrorCategoryMalformedResponse  = "malformed_response"
	// The destination is on a network this gateway does not carry traffic to: internal, link-local, loopback
	// or the cloud metadata address. The SWG is a forward proxy to the public internet, and internal
	// destinations are reached as published applications through a connector — so this is a routing answer,
	// not a fault. It has its own category because it is the one refusal with a specific remedy, and because
	// telling it apart from a timeout or a refused connection is what stops an administrator debugging their
	// network for an hour (2026-08-30: a steered Mac could not open its own deployment's Console, and the
	// message it was given described an attack).
	EdgeSWGHTTPEgressUpstreamErrorCategoryInternalDestination = "internal_destination"
	EdgeSWGHTTPEgressUpstreamErrorCategoryOtherNonSecret      = "other_nonsecret"
)
