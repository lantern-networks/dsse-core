package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// enrolment_token_fleet_routes.go — the control plane answering "may this token be spent".
//
// The other half of enrolment_token_remote.go. A device reaches an EDGE to enrol, because that is where the
// transport is; the decision that a certificate may be issued is the CONTROL PLANE's, because that is where
// authority lives. So the Edge asks, and the single conditional write stays exactly where it always was.
//
// ★ THE SAME AUTHENTICATION THE FLEET CHANNEL ALREADY USES. An Edge reaches its control plane with an admin
// API token — that is what POST /admin/fleet/config-status is authenticated with, and what the config pull
// carries — so these sit beside it under /admin/fleet and are gated on admin.enrollment.write. Inventing a
// second shared bearer for one pair of routes would mean a second credential to rotate, and the first attempt
// at this file did exactly that: it checked the AUDIT-INGEST token while the Edge sent the CONFIG-SOURCE one,
// which are separately configurable and in this deployment are not the same string.
//
// ★ THE ANSWER CARRIES A REASON, NOT A SENTENCE. The Edge maps it back to the same sentinel error its local
// store returned, because /enroll logs "already spent" differently from "never existed" — and treats an
// unknown secret as possibly-the-shared-token and falls THROUGH to the other eligibility modes. A reason
// flattened into prose across the wire would have broken the shared-token path silently.

func registerEnrolmentTokenFleetRoutes(mux *http.ServeMux,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, tokens enrolltoken.Authority,
	logf func(string, ...interface{})) {
	if tokens == nil || adminEndpoint == nil {
		// No authority to ask. Registering the routes anyway would answer "unknown" to every question, which a
		// caller cannot tell from "that token does not exist" — and would quietly stop every enrolment.
		return
	}

	mux.HandleFunc("POST /admin/fleet/enrolment-token/verify", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		var req enrolmentTokenRemoteRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tok, err := tokens.Verify(req.Secret, req.TenantID, time.Now().UTC())
		if err != nil {
			// 200 with a reason, not an HTTP error: this is an ANSWER to a question, and the Edge has to be
			// able to tell "no, because it is spent" from "the authority did not respond". An HTTP status
			// cannot carry that difference without the Edge guessing.
			if rec, ok := w.(*adminAuditStatusRecorder); ok {
				rec.businessFailure = true
			}
			writeJSON(w, http.StatusOK, enrolmentTokenRefusal(err))
			return
		}
		writeJSON(w, http.StatusOK, enrolmentTokenRemoteResponse{Token: tok})
	}))

	mux.HandleFunc("POST /admin/fleet/enrolment-token/spend", adminEndpoint("admin.enrollment.write", func(w http.ResponseWriter, r *http.Request) {
		var req enrolmentTokenRemoteRequest
		if err := decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tok, err := spendEnrolmentToken(r.Context(), tokens, req.ID, req.TenantID, req.DeviceID, time.Now().UTC())
		if err != nil {
			if logf != nil {
				// The operator's copy of why. The Edge gets the reason and turns it into its own log line, but
				// the authority is where a burst of refusals is worth seeing.
				logf("enrolment_token_spend_refused id=%q tenant=%q device=%q reason=%q",
					req.ID, req.TenantID, req.DeviceID, enrolmentTokenReason(err))
			}
			if rec, ok := w.(*adminAuditStatusRecorder); ok {
				rec.businessFailure = true
			}
			writeJSON(w, http.StatusOK, enrolmentTokenRefusal(err))
			return
		}
		if logf != nil {
			logf("enrolment_token_spent id=%q tenant=%q device=%q", req.ID, req.TenantID, req.DeviceID)
		}
		writeJSON(w, http.StatusOK, enrolmentTokenRemoteResponse{Token: tok})
	}))
	if logf != nil {
		logf("enrolment-token authority: POST /admin/fleet/enrolment-token/{verify,spend} registered — Edges ask here " +
			"rather than holding a database of their own")
	}
}

// enrolmentTokenRefusal is the authority's answer to a token it will not honour: the reason word every Edge
// branches on, plus — for a spent token — which machine spent it and when.
//
// ★ THE FACTS LIVE ONLY HERE. An Edge holds no token store; it asks. So "already been used, by X at T" can
// only be assembled at the authority, and if it is not put on the wire the operator's log can never say it.
// Measured 2026-09-01: an hour spent on a Mac quietly sending another machine's spent token.
func enrolmentTokenRefusal(err error) enrolmentTokenRemoteResponse {
	resp := enrolmentTokenRemoteResponse{Error: enrolmentTokenReason(err)}
	var used *enrolltoken.AlreadyUsedError
	if errors.As(err, &used) {
		resp.UsedBy, resp.UsedAt = used.UsedBy, used.UsedAt
	}
	return resp
}
