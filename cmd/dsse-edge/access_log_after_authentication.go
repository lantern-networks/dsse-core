package main

import (
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// access_log_after_authentication.go — what the access log says about a flow a sign-in let through.
//
// ★★★ THE LOG SAID "AUTHENTICATION REQUIRED" FOR THE CONNECTION AUTHENTICATION LET THROUGH (2026-11-04, found by
// walking the step-up for a private application on a Windows device). The evaluator decides what a rule REQUIRES;
// whether the user has met that requirement is checked separately, against the grant their sign-in produced. Both
// the held flow that resumed after the sign-in and every later flow covered by the same grant were recorded with
// the evaluator's word — authenticate_required — so the logs showed six requests for authentication and not one
// access, for a session in which the user signed in and reached the application. Reading the log, nobody could
// tell that access had been granted, or to whom.
//
// So a flow that is let through because the required authentication was verified is recorded as allowed, says
// why, and keeps what the rule required. A flow that is HELD for authentication keeps authenticate_required.

const reasonCodeAuthenticationSatisfied = "authentication_satisfied"

func decisionAllowedByAuthentication(dec model.AccessDecision) model.AccessDecision {
	out := dec
	out.Decision = "allow"
	reason := "Allowed: the interactive authentication this rule requires was completed."
	out.Reason = &reason
	out.ReasonCodes = append(append([]string(nil), dec.ReasonCodes...), reasonCodeAuthenticationSatisfied)
	metadata := make(map[string]any, len(dec.Metadata)+1)
	for k, v := range dec.Metadata {
		metadata[k] = v
	}
	metadata["required_decision"] = dec.Decision
	out.Metadata = metadata
	return out
}

// decisionWasAllowedByAuthentication is always recorded: an access a sign-in granted is the record of that
// sign-in being used, whatever the rule says about logging ordinary allowed traffic.
func decisionWasAllowedByAuthentication(dec model.AccessDecision) bool {
	if dec.Decision != "allow" {
		return false
	}
	for _, code := range dec.ReasonCodes {
		if code == reasonCodeAuthenticationSatisfied {
			return true
		}
	}
	return false
}

// ★★ AND A FLOW REFUSED AT THE LAST RE-CHECK WAS RECORDED NOWHERE (2026-11-05). Once a live grant
// was found, the first record was left to the resume, so the re-check immediately before forwarding — which can
// refuse: the device was revoked, the policy changed, the grant was used up, the decision could not be made —
// returned with a line on stderr and no access record at all. The refusal is the record of that flow.
const reasonCodeResumeRefused = "authentication_resume_refused"

// decisionRefusedAtResume is what is recorded when that re-check does not permit the flow. A decision the policy
// itself now makes (deny, and the like) is recorded as it is. Anything else — no decision could be made, the
// sign-in no longer satisfies the rule, the configuration changed during the check — is recorded as a denial of
// the original request, saying why, and never as allowed.
func decisionRefusedAtResume(original, current model.AccessDecision) model.AccessDecision {
	verdict := strings.TrimSpace(current.Decision)
	if verdict != "" && verdict != "allow" && current.TenantID == original.TenantID &&
		!decisionRequiresOIDCRedirect(verdict) && !decisionPermitsConnectorRoute(verdict) {
		return current
	}
	out := original
	// A decision of its own. Every log row has its own id (alog_…), so reusing the original's would not overwrite
	// the held row; but the refusal is a different decision from the one the flow was held under, and the related
	// records are looked up by access_decision_id. held_decision_id names the held one.
	out.ID = randomEdgeID("dec_", time.Now().UTC())
	out.Decision = "deny"
	reason := "Denied: the re-check immediately before forwarding did not permit this connection."
	out.Reason = &reason
	out.ReasonCodes = append(append([]string(nil), original.ReasonCodes...), reasonCodeResumeRefused)
	metadata := make(map[string]any, len(original.Metadata)+2)
	for k, v := range original.Metadata {
		metadata[k] = v
	}
	metadata["required_decision"] = original.Decision
	if original.ID != "" {
		metadata["held_decision_id"] = original.ID
	}
	if verdict != "" {
		metadata["resume_decision"] = verdict
	}
	out.Metadata = metadata
	return out
}
