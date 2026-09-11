package main

import (
	"net/http"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// enrolled_identity_claim_fleet_routes.go — the control plane answering "may this node claim that identity".
//
// The other half of enrolled_identity_claim_remote.go, and the same shape as the enrolment-token routes beside
// it: a device reaches an EDGE to enrol, and the one-time decision belongs to the authority. The single
// conditional write is unchanged and still in one place; only the caller moved.
//
// ★ THE ANSWER IS A BOOLEAN AND AN ERROR, AND THEY ARE NOT THE SAME. "No, somebody already holds it" is an
// answer; "I could not decide" is not. They are separated on the wire for the reason the client separates them:
// treating a failure as "not claimed" is exactly how two issuers both mint a certificate for one device name.

func registerEnrolledIdentityClaimFleetRoutes(mux *http.ServeMux,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, claims enrolledinventory.IdentityClaimer,
	logf func(string, ...interface{})) {
	if claims == nil || adminEndpoint == nil {
		// Nothing authoritative to ask. Registering the routes anyway would answer "claimed" to everything or
		// "not claimed" to everything, and either is worse than an Edge discovering there is no authority.
		return
	}
	decode := func(w http.ResponseWriter, r *http.Request) (identityClaimRemoteRequest, bool) {
		var req identityClaimRemoteRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return req, false
		}
		return req, true
	}

	// control-plane-only: the fleet surface exists only where the fleet is aggregated (measured: an Edge answers 404)
	mux.HandleFunc("POST /admin/fleet/identity-claim/claim", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		req, ok := decode(w, r)
		if !ok {
			return
		}
		claimed, err := claims.ClaimIdentity(r.Context(), req.TenantID, req.Identity, req.Grant)
		if err != nil {
			// A failure the authority itself had. Reported as an error rather than as "not claimed", because
			// the caller must refuse the enrolment rather than proceed on an unknown outcome.
			writeJSON(w, http.StatusOK, identityClaimRemoteResponse{Error: err.Error()})
			return
		}
		if logf != nil && !claimed {
			logf("identity_claim_refused tenant=%q identity=%q grant=%d reason=%q", req.TenantID, req.Identity,
				req.Grant, "another issuer already holds this identity under this or a newer grant")
		}
		writeJSON(w, http.StatusOK, identityClaimRemoteResponse{Claimed: claimed})
	}))

	// control-plane-only: the fleet surface exists only where the fleet is aggregated (measured: an Edge answers 404)
	mux.HandleFunc("POST /admin/fleet/identity-claim/release", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		req, ok := decode(w, r)
		if !ok {
			return
		}
		if err := claims.ReleaseIdentity(r.Context(), req.TenantID, req.Identity, req.Grant); err != nil {
			writeJSON(w, http.StatusOK, identityClaimRemoteResponse{Error: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, identityClaimRemoteResponse{})
	}))

	// control-plane-only: the fleet surface exists only where the fleet is aggregated (measured: an Edge answers 404)
	mux.HandleFunc("POST /admin/fleet/identity-claim/backfill", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		req, ok := decode(w, r)
		if !ok {
			return
		}
		recorded, err := claims.BackfillClaims(r.Context(), req.Claims)
		if err != nil {
			writeJSON(w, http.StatusOK, identityClaimRemoteResponse{Error: err.Error()})
			return
		}
		if logf != nil && recorded > 0 {
			// Worth a line: this is an Edge handing the authority identities that were enrolled before the
			// shared claim existed, and an empty claim table is what hands an existing fleet away.
			logf("identity_claims_backfilled recorded=%d at=%s", recorded, time.Now().UTC().Format(time.RFC3339))
		}
		writeJSON(w, http.StatusOK, identityClaimRemoteResponse{Recorded: recorded})
	}))
	if logf != nil {
		logf("identity-claim authority: POST /admin/fleet/identity-claim/{claim,release,backfill} registered — " +
			"Edges ask here rather than holding a database of their own")
	}
}
