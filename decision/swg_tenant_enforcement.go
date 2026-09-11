package decision

import (
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

type swgTenantEnforcementContext struct {
	Configured                 bool
	DefaultTLSDecryptRequired  bool
	MacCATrustRequired         bool
	TenantRestrictionRule      *model.SWGTenantRestrictionRule
	TLSBypassRule              *model.SWGTLSBypassRule
	HeaderInjectionApplicable  bool
	HeaderInjectionSuppressed  bool
	HeaderInjectionAction      bool
	RuntimeTLSObserved         bool
	RuntimeHeaderObserved      bool
	HeaderValueMaterialPresent bool
}

func (e Evaluator) swgTenantEnforcementContextFor(policy model.Policy, req model.DecisionRequest, inspectionCtx tlsInspectionReadinessContext) swgTenantEnforcementContext {
	if !requestIsSWGHTTPS(req) {
		return swgTenantEnforcementContext{}
	}
	if req.SaaSApplicationID == "" && req.SaaSProvider == "" && req.SaaSCategory == "" {
		return swgTenantEnforcementContext{}
	}

	ctx := swgTenantEnforcementContext{
		DefaultTLSDecryptRequired: inspectionCtx.Configured && inspectionCtx.Profile.TLSInterceptionEnabled,
		MacCATrustRequired:        inspectionCtx.Configured && inspectionCtx.Profile.TLSInterceptionEnabled,
		RuntimeTLSObserved:        false,
		RuntimeHeaderObserved:     false,
	}
	if rule, ok := e.firstSWGTenantRestrictionRule(req, policy); ok {
		ruleCopy := rule
		ctx.TenantRestrictionRule = &ruleCopy
		ctx.HeaderInjectionApplicable = true
	}
	if rule, ok := e.firstSWGTLSBypassRule(req, policy); ok {
		ruleCopy := rule
		ctx.TLSBypassRule = &ruleCopy
		ctx.HeaderInjectionSuppressed = ctx.HeaderInjectionApplicable
	}
	ctx.HeaderInjectionAction = ctx.HeaderInjectionApplicable && ctx.TLSBypassRule == nil && ctx.DefaultTLSDecryptRequired
	ctx.Configured = ctx.DefaultTLSDecryptRequired || ctx.TenantRestrictionRule != nil || ctx.TLSBypassRule != nil
	return ctx
}

func requestIsSWGHTTPS(req model.DecisionRequest) bool {
	serviceFamily := normalizedRiskValue(req.ServiceFamily)
	protocol := normalizedRiskValue(req.Protocol)
	return serviceFamily == "https" || serviceFamily == "saas" || (req.DestinationPort == 443 && (protocol == "tcp" || protocol == ""))
}

func (e Evaluator) firstSWGTenantRestrictionRule(req model.DecisionRequest, policy model.Policy) (model.SWGTenantRestrictionRule, bool) {
	for _, rule := range e.PolicyBundle.SWGTenantRestrictionRules {
		if !activeSWGRule(rule.Status) {
			continue
		}
		if strings.TrimSpace(req.TenantID) != "" && rule.TenantID != "" && rule.TenantID != req.TenantID {
			continue
		}
		if !tenantMatches(rule.TenantID, e.PolicyBundle.TenantID, policy.TenantID, req.TenantID) {
			continue
		}
		if swgTenantRestrictionRuleMatches(rule, req) {
			return rule, true
		}
	}
	return model.SWGTenantRestrictionRule{}, false
}

func swgTenantRestrictionRuleMatches(rule model.SWGTenantRestrictionRule, req model.DecisionRequest) bool {
	ruleAppID := strings.TrimSpace(rule.SaaSApplicationID)
	if ruleAppID != "" && ruleAppID == strings.TrimSpace(req.SaaSApplicationID) {
		return true
	}
	ruleProvider := normalizedRiskValue(rule.Provider)
	return ruleProvider != "" && ruleProvider == normalizedRiskValue(req.SaaSProvider)
}

func (e Evaluator) firstSWGTLSBypassRule(req model.DecisionRequest, policy model.Policy) (model.SWGTLSBypassRule, bool) {
	for _, rule := range e.PolicyBundle.SWGTLSBypassRules {
		if !activeSWGRule(rule.Status) {
			continue
		}
		if !tenantMatches(rule.TenantID, e.PolicyBundle.TenantID, policy.TenantID, req.TenantID) {
			continue
		}
		if swgTLSBypassRuleMatches(rule, req) {
			return rule, true
		}
	}
	return model.SWGTLSBypassRule{}, false
}

func activeSWGRule(status string) bool {
	return normalizedRiskValue(status) == "" || normalizedRiskValue(status) == "active"
}

func swgTLSBypassRuleMatches(rule model.SWGTLSBypassRule, req model.DecisionRequest) bool {
	switch normalizedRiskValue(rule.MatchType) {
	case "fqdn", "domain":
		return swgDomainRuleMatches(rule.Pattern, req.FQDN, req.SNI, req.Destination)
	case "sni":
		return swgDomainRuleMatches(rule.Pattern, req.SNI)
	case "saas_application_id":
		return strings.TrimSpace(rule.SaaSApplicationID) != "" && strings.TrimSpace(rule.SaaSApplicationID) == strings.TrimSpace(req.SaaSApplicationID)
	case "category":
		return normalizedRiskValue(rule.Category) != "" && normalizedRiskValue(rule.Category) == normalizedRiskValue(req.SaaSCategory)
	default:
		return false
	}
}

func swgDomainRuleMatches(pattern string, candidates ...string) bool {
	for _, candidate := range candidates {
		if _, _, ok := saasDomainPatternMatches(candidate, pattern); ok {
			return true
		}
	}
	return false
}

func applySWGTenantEnforcementMetadata(metadata map[string]any, ctx swgTenantEnforcementContext) {
	metadata["swg_tenant_enforcement_preflight"] = "policy_layer"
	metadata["swg_default_tls_decryption_required"] = ctx.DefaultTLSDecryptRequired
	metadata["swg_tls_bypass_policy"] = "per_destination_bypass_list"
	metadata["swg_tls_bypass_applied"] = ctx.TLSBypassRule != nil
	metadata["swg_tls_runtime_decryption_observed"] = ctx.RuntimeTLSObserved
	metadata["swg_header_injection_runtime_observed"] = ctx.RuntimeHeaderObserved
	metadata["swg_macos_ca_trust_required"] = ctx.MacCATrustRequired
	metadata["swg_macos_ca_trust_observed"] = false
	if ctx.TenantRestrictionRule != nil {
		metadata["swg_tenant_restriction_rule_id"] = ctx.TenantRestrictionRule.ID
		metadata["swg_tenant_restriction_header_name"] = ctx.TenantRestrictionRule.HeaderName
		metadata["swg_tenant_restriction_header_value_ref"] = ctx.TenantRestrictionRule.HeaderValueRef
		metadata["swg_tenant_restriction_header_value_kind"] = ctx.TenantRestrictionRule.HeaderValueKind
		metadata["swg_tenant_restriction_header_value_material_in_decision"] = ctx.HeaderValueMaterialPresent
		metadata["swg_tenant_restriction_header_injection_applicable"] = ctx.HeaderInjectionApplicable
		metadata["swg_tenant_restriction_header_injection_applied"] = ctx.HeaderInjectionAction
		metadata["swg_tenant_restriction_header_injection_suppressed_by_bypass"] = ctx.HeaderInjectionSuppressed
	}
	if ctx.TLSBypassRule != nil {
		metadata["swg_tls_bypass_rule_id"] = ctx.TLSBypassRule.ID
		metadata["swg_tls_bypass_match_type"] = ctx.TLSBypassRule.MatchType
		metadata["swg_tls_bypass_reason"] = ctx.TLSBypassRule.Reason
	}
}

func appendSWGTenantEnforcementReasonCodes(reasonCodes []string, ctx swgTenantEnforcementContext) []string {
	reasonCodes = appendUniqueString(reasonCodes, "swg_saas_tenant_enforcement_preflight")
	if ctx.DefaultTLSDecryptRequired {
		reasonCodes = appendUniqueString(reasonCodes, "swg_default_tls_decryption_required")
	}
	if ctx.HeaderInjectionAction {
		reasonCodes = appendUniqueString(reasonCodes, "swg_tenant_restriction_header_injection_planned")
	}
	if ctx.TLSBypassRule != nil {
		reasonCodes = appendUniqueString(reasonCodes, "swg_tls_bypass_applied")
	}
	return reasonCodes
}

func appendSWGTenantEnforcementActions(actions []model.DecisionAction, ctx swgTenantEnforcementContext, req model.DecisionRequest, policy model.Policy) []model.DecisionAction {
	if ctx.HeaderInjectionAction && ctx.TenantRestrictionRule != nil {
		target := valueOrDefault(req.SaaSApplicationID, req.ApplicationID)
		actions = append(actions, model.DecisionAction{
			Type:   "inject_saas_tenant_restriction_header",
			Target: stringPtr(target),
			Metadata: map[string]any{
				"policy_id":                         policy.ID,
				"saas_application_id":               req.SaaSApplicationID,
				"saas_provider":                     req.SaaSProvider,
				"swg_tenant_restriction_rule_id":    ctx.TenantRestrictionRule.ID,
				"header_name":                       ctx.TenantRestrictionRule.HeaderName,
				"header_value_ref":                  ctx.TenantRestrictionRule.HeaderValueRef,
				"header_value_kind":                 ctx.TenantRestrictionRule.HeaderValueKind,
				"header_value_material_in_decision": false,
				"tls_decryption_mode":               "default_decrypt",
				"runtime_tls_decryption_observed":   false,
				"runtime_header_injection_observed": false,
			},
		})
		if ctx.TenantRestrictionRule.Provider == "microsoft_365" {
			if ref, ok := ctx.TenantRestrictionRule.Metadata["restriction_context_ref"].(string); ok && ref != "" {
				actions[len(actions)-1].Metadata["restriction_context_ref"] = ref
			}
		}

	}
	if ctx.TLSBypassRule != nil {
		actions = append(actions, model.DecisionAction{
			Type: "emit_audit_event",
			Metadata: map[string]any{
				"audit_event_type":                   "swg_tls_bypass_preflight",
				"policy_id":                          policy.ID,
				"saas_application_id":                req.SaaSApplicationID,
				"swg_tls_bypass_rule_id":             ctx.TLSBypassRule.ID,
				"swg_tls_bypass_match_type":          ctx.TLSBypassRule.MatchType,
				"swg_tls_bypass_reason":              ctx.TLSBypassRule.Reason,
				"tenant_header_injection_suppressed": ctx.HeaderInjectionSuppressed,
				"runtime_tls_decryption_observed":    false,
				"runtime_header_injection_observed":  false,
				"header_value_material_in_decision":  false,
				"network_extension_runtime_used":     false,
			},
		})
	}
	return actions
}
