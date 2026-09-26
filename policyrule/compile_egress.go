package policyrule

import (
	"log"
	"strconv"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

// EgressResolver resolves an authored egress rule's subjects: its source to device identities (for
// source restriction) and its destination to network addresses (FQDN/IP, for destination matching).
type EgressResolver interface {
	SourceDeviceTokens(tenant string, ids []string) []string
	EndpointAddresses(tenant string, ids []string) []string
	// ServicePorts is retained for resolver compatibility; ports alone cannot
	// establish named-service transport scope. Implement ServiceTransportPorts
	// as well to retain exact protocol/port pairs; otherwise the rule matches nothing.
	ServicePorts(tenant string, serviceID string) []int
}

// CompileEgressPolicies compiles authored egress rules (allow / deny / authenticate) into model.Policy
// entries, each matched by destination FQDN, restricted to the authored source's device identities
// (device_id ∈ source), AND SCOPED TO THE RULE'S TRANSPORT PAIRS (protocol + destination_port; empty
// service ⇒ Any, i.e. port-agnostic) — without the port scope a rule for one service (e.g. SSH tcp/22) matched
// EVERY port. `authenticate` compiles to require_reauthentication (the step-up decision the evaluator + egress
// gate act on; the OOB-browser trigger for a steered flow is a separate wiring — see the steer-mux path). A
// source that resolves to no device compiles fail-closed (a never-matching sentinel device), never any-source.
// Inspection bypass is handled separately via the engine's raw-forward set, not here.
func CompileEgressPolicies(tenant string, rules []Rule, resolver EgressResolver) []model.Policy {
	var out []model.Policy
	for _, r := range rules {
		if r.Plane != PlaneEgress || r.Status != StatusActive {
			continue
		}
		var dec string
		var stepUpMeta map[string]any
		switch r.Action.Access {
		case AccessAllow:
			dec = "allow"
		case AccessDeny:
			dec = "deny"
		case AccessAuthenticate:
			// require_reauthentication is the decision the evaluator reads step-up requirements from (via the
			// policy metadata below) and the SWG egress gate redirects to the IdP for.
			dec = "require_reauthentication"
			stepUpMeta = map[string]any{}
			if r.Action.RequiredIdPID != "" {
				stepUpMeta["required_idp_id"] = r.Action.RequiredIdPID
			}
			if r.Action.MinACR != "" {
				stepUpMeta["min_acr"] = r.Action.MinACR
			}
			if len(r.Action.RequiredAMR) > 0 {
				stepUpMeta["required_amr"] = strings.Join(r.Action.RequiredAMR, ",")
			}
			if r.Action.MaxAgeSeconds > 0 {
				stepUpMeta["max_age_seconds"] = r.Action.MaxAgeSeconds
			}
		default:
			continue
		}
		transports, resolved := egressServiceConditions(tenant, r.ServiceID, resolver)
		if !resolved {
			log.Printf("policyrule: egress rule %q service is unresolved or invalid — the rule matches nothing (including deny/authenticate); repair the service catalog", r.ID)
		}
		// Source: explicit Any => no source condition. Otherwise split the authored selectors into IDENTITY
		// groups (idgroup:<name> ⇒ a user_groups condition matched against the authenticated session's groups —
		// this is what lets a person/group rule apply to an agentless browser) and DEVICE/asset ids (⇒ a
		// device_id condition, with a fail-closed sentinel when they don't resolve). A rule usually carries one
		// kind; if it carries both they compile as an OR (one policy per source restriction). See
		// docs/published_app_access_egress_unification_design.md.
		sourceAny := IsAnySubject(r.Source)
		var sourceConds []map[string]any // each entry is one source restriction; >1 ⇒ OR via separate policies
		if sourceAny {
			sourceConds = []map[string]any{{}}
		} else {
			var deviceIDs []string
			var identityGroups []any
			var identityUsers []any
			var agentIDs []any
			for _, s := range r.Source {
				if g, ok := IdentityGroupToken(s); ok {
					identityGroups = append(identityGroups, g)
					continue
				}
				if u, ok := IdentityUserToken(s); ok { // iduser:<id> ⇒ an individual IdP user (user_id), never a device
					identityUsers = append(identityUsers, u)
					continue
				}
				if a, ok := AgentToken(s); ok { // nhi:<id> ⇒ an agent actor (actor_nhi_id), never a device
					agentIDs = append(agentIDs, a)
					continue
				}
				deviceIDs = append(deviceIDs, s)
			}
			if len(deviceIDs) > 0 {
				var deviceVals []any
				for _, d := range resolver.SourceDeviceTokens(tenant, deviceIDs) {
					deviceVals = append(deviceVals, d)
				}
				if len(deviceVals) == 0 {
					deviceVals = []any{sourceNoMatchSentinel}
				}
				sourceConds = append(sourceConds, map[string]any{"device_id": deviceVals})
			}
			if len(identityGroups) > 0 {
				sourceConds = append(sourceConds, map[string]any{"user_groups": identityGroups})
			}
			if len(identityUsers) > 0 { // iduser:<id> ⇒ match the decision request's user_id (an individual person)
				sourceConds = append(sourceConds, map[string]any{"user_id": identityUsers})
			}
			if len(agentIDs) > 0 { // nhi:<id> ⇒ match the decision request's actor_nhi_id (the agent tool boundary rides on AllowedToolIDs below)
				sourceConds = append(sourceConds, map[string]any{"actor_nhi_id": agentIDs})
			}
			if len(sourceConds) == 0 { // no resolvable source ⇒ fail closed
				sourceConds = []map[string]any{{"device_id": []any{sourceNoMatchSentinel}}}
			}
		}
		// appendPolicy emits one compiled policy per (source restriction × the given host condition), folding in
		// the exact protocol/port combinations. Conditions are copied per variant so the OR does not
		// alias one map across policies.
		var riskVals []any // gate on the subject's CURRENT risk (device or user marked ≥ RiskAtLeast); nil ⇒ no gate
		for _, s := range RiskSeveritiesAtLeast(r.RiskAtLeast) {
			riskVals = append(riskVals, s)
		}
		appendPolicy := func(idSuffix string, hostConditions map[string]any) {
			for si, sc := range sourceConds {
				for _, transport := range transports {
					conditions := map[string]any{}
					for k, v := range hostConditions {
						conditions[k] = v
					}
					for k, v := range sc {
						conditions[k] = v
					}
					for k, v := range transport {
						conditions[k] = v
					}
					if len(riskVals) > 0 { // risk_state_severity ∈ {threshold..critical} ⇒ rule bites only when high-risk
						conditions["risk_state_severity"] = riskVals
					}
					suffix := idSuffix
					if len(sourceConds) > 1 {
						suffix = idSuffix + "-s" + strconv.Itoa(si)
					}
					if len(transports) > 1 {
						suffix += "-" + transport["protocol"].(string)
					}
					out = append(out, model.Policy{
						ID:             "rule-egress-" + r.ID + suffix,
						TenantID:       tenant,
						Name:           "Authored egress rule " + r.ID,
						Priority:       r.Priority,
						Status:         "active",
						Conditions:     conditions,
						Action:         model.PolicyAction{Decision: dec},
						DLP:            r.Action.DLP,     // Access × Inspection × DLP — carry the rule's DLP onto the policy
						AllowedToolIDs: r.AllowedToolIDs, // agent rule (Who = nhi:) ⇒ the agentic tool boundary
						Metadata:       stepUpMeta,
					})
				}
			}
		}
		// Destination: explicit Any => one policy with no host condition (any destination). Otherwise, for each
		// resolved destination, emit BOTH an fqdn-keyed and an sni-keyed policy (OR via separate policies). A
		// STEERED HTTPS flow is identified by its TLS SNI — the browser connects by IP, so the flow's FQDN is the
		// IP, not the hostname — while a plain SWG/HTTP egress sets FQDN. Emitting only fqdn made a per-site
		// egress deny silently miss the steered browser flow (the SNI is the robust key, as the direct SWG
		// policies use).
		if IsAnySubject(r.Destination) {
			appendPolicy("-any", map[string]any{})
		} else {
			resolved := 0
			for i, addr := range resolver.EndpointAddresses(tenant, r.Destination) {
				if strings.TrimSpace(addr) == "" {
					continue
				}
				resolved++
				appendPolicy("-"+strconv.Itoa(i)+"-fqdn", map[string]any{"fqdn": addr})
				appendPolicy("-"+strconv.Itoa(i)+"-sni", map[string]any{"sni": addr})
			}
			// A non-Any destination that resolves to ZERO addresses would emit NO policy at all, so the authored
			// rule silently VANISHES (fail-open review #10) — a per-site DENY stops enforcing when its endpoint is
			// removed/unresolved. Surface it, and emit a match-nothing sentinel policy so the rule stays PRESENT
			// (visible in the effective set) instead of disappearing. (Enforcement against an unresolvable host
			// cannot be reconstructed here — the log is how the operator learns their rule is degraded.)
			if resolved == 0 {
				log.Printf("policyrule: egress rule %q destination resolved to ZERO addresses — the rule matches nothing (a DENY here is NOT enforcing); check the destination in the asset catalog", r.ID)
				appendPolicy("-nomatch", map[string]any{"fqdn": destinationNoMatchSentinel})
			}
		}
	}
	return out
}
