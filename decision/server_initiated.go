package decision

import (
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// Server-Initiated Client Access Control. A server->client (inbound-to-endpoint) flow
// is governed separately and is DEFAULT-DENY: it is allowed only when it matches an active, non-expired
// Legacy Exception (mode allow|observe|warn). This prevents a compromised server from reaching client
// endpoints (lateral movement) unless explicitly authorized.

// isServerInitiated reports whether a flow is server-originated (server->client). The Endpoint Agent
// classifies inbound connections and sets connection_initiator=server (or source/destination roles).
func isServerInitiated(req model.DecisionRequest) bool {
	switch strings.ToLower(strings.TrimSpace(req.ConnectionInitiator)) {
	case "server", "server_initiated":
		return true
	}
	return strings.EqualFold(strings.TrimSpace(req.SourceRole), "server") &&
		strings.EqualFold(strings.TrimSpace(req.DestinationRole), "client")
}

func (e Evaluator) serverInitiatedDecisionFor(req model.DecisionRequest, now time.Time) (decisionValue, reason string, reasonCodes []string) {
	ex, matched := e.matchLegacyException(req, now)
	if !matched {
		return "deny", "Server-initiated access denied by default-deny (no active Legacy Exception).", []string{"server_initiated_default_deny"}
	}
	switch strings.ToLower(strings.TrimSpace(ex.Mode)) {
	case "deny":
		return "deny", "Server-initiated access denied by Legacy Exception.", []string{"server_initiated_legacy_exception_deny"}
	case "warn":
		return "allow", "Server-initiated access allowed (warn) by Legacy Exception.", []string{"server_initiated_legacy_exception_warn"}
	case "observe":
		return "allow", "Server-initiated access allowed (observe) by Legacy Exception.", []string{"server_initiated_legacy_exception_observe"}
	default: // allow
		return "allow", "Server-initiated access allowed by Legacy Exception.", []string{"server_initiated_legacy_exception_allow"}
	}
}

// matchLegacyException returns the first active, non-expired exception matching the flow. An empty
// exception field is a wildcard; port 0 is a wildcard.
func (e Evaluator) matchLegacyException(req model.DecisionRequest, now time.Time) (LegacyException, bool) {
	for _, ex := range e.LegacyExceptions {
		if !ex.Active {
			continue
		}
		if !ex.ExpiresAt.IsZero() && !now.Before(ex.ExpiresAt) {
			continue // expired
		}
		if !legacyFieldMatch(ex.SourceServer, req.SourceServer) {
			continue
		}
		if !legacyFieldMatch(ex.DeviceGroup, req.DeviceGroup) {
			continue
		}
		if !legacyFieldMatch(ex.ServiceFamily, req.ServiceFamily) {
			continue
		}
		if !legacyFieldMatch(ex.Protocol, req.Protocol) {
			continue
		}
		if ex.Port != 0 && ex.Port != req.DestinationPort {
			continue
		}
		return ex, true
	}
	return LegacyException{}, false
}

func legacyFieldMatch(exVal, reqVal string) bool {
	exVal = strings.TrimSpace(exVal)
	if exVal == "" {
		return true // wildcard
	}
	return strings.EqualFold(exVal, strings.TrimSpace(reqVal))
}
