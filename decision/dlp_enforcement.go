package decision

import (
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

// firstDLPRule returns the first active DLP rule that applies to the request (matched by SaaS application id or
// provider, tenant-scoped; a rule with no selector is tenant-wide). DLP is thus an option ON an egress
// destination, mirroring tenant restriction — not a separate policy.
func (e Evaluator) firstDLPRule(req model.DecisionRequest, policy model.Policy) (model.DLPRule, bool) {
	for _, rule := range e.PolicyBundle.DLPRules {
		if !activeSWGRule(rule.Status) {
			continue
		}
		if !tenantMatches(rule.TenantID, e.PolicyBundle.TenantID, policy.TenantID, req.TenantID) {
			continue
		}
		if dlpRuleMatches(rule, req) {
			return rule, true
		}
	}
	return model.DLPRule{}, false
}

func dlpRuleMatches(rule model.DLPRule, req model.DecisionRequest) bool {
	appID := strings.TrimSpace(rule.SaaSApplicationID)
	if appID != "" && appID == strings.TrimSpace(req.SaaSApplicationID) {
		return true
	}
	provider := normalizedRiskValue(rule.Provider)
	if provider != "" && provider == normalizedRiskValue(req.SaaSProvider) {
		return true
	}
	// No selector → tenant-wide DLP (applies to any intercepted egress for the tenant).
	return appID == "" && provider == ""
}

// dlpInspectAction is the decision directive the egress handler reads to inspect the decrypted body/files. It
// carries only non-secret configuration (identifier types, threshold, action, rule id).
func dlpInspectAction(rule model.DLPRule) model.DecisionAction {
	return dlpInspectDirective(rule.ID, rule.Identifiers, rule.MinCount, rule.OnMatch, rule.InstanceScope, "")
}

// dlpInspectActionFromSpec builds the directive from a policy-attached DLP spec (Policy.DLP); ruleID is the
// matched policy's id so audit/telemetry can attribute the inspection to the egress rule. When the spec references
// a named DLP Policy object (spec.PolicyID, S5), the directive carries that id and the edge resolves the policy's
// detectors/action/instance-scope; the inline fields are the fallback.
func dlpInspectActionFromSpec(ruleID string, spec model.DLPSpec) model.DecisionAction {
	return dlpInspectDirective(ruleID, spec.Identifiers, spec.MinCount, spec.OnMatch, spec.InstanceScope, spec.PolicyID)
}

func dlpInspectDirective(ruleID string, identifiers []string, minCount int, onMatch, instanceScope, policyID string) model.DecisionAction {
	onMatch = strings.TrimSpace(onMatch)
	if onMatch == "" {
		onMatch = "observe"
	}
	md := map[string]any{
		"dlp_rule_id": ruleID,
		"identifiers": identifiers,
		"min_count":   minCount,
		"action":      onMatch,
	}
	// Instance-aware action (the sovereign "here not there"): carry the scope so the egress handler — which sees
	// the signed-in account — applies the rule only for the matching destination instance class.
	if s := strings.TrimSpace(instanceScope); s != "" && s != "any" {
		md["instance_scope"] = s
	}
	// S5: a reference to a named DLP Policy object — the edge resolves it into detectors/action/instance-scope.
	if p := strings.TrimSpace(policyID); p != "" {
		md["dlp_policy_id"] = p
	}
	return model.DecisionAction{Type: "dlp_inspect", Metadata: md}
}
