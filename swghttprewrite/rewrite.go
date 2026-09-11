package swghttprewrite

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

const injectTenantRestrictionHeaderAction = "inject_saas_tenant_restriction_header"

// enterpriseControlledRequestHeaders are header names whose value only the Edge (operator config) may set on
// an upstream request — the SaaS tenant-restriction headers this package injects, plus Restrict-Access-Context
// (the M365 companion header that scopes which tenant's restriction policy applies). They are Del'd from EVERY
// client request before any injection decision: Set-on-inject alone only overwrites the one header the
// matching policy injects, so when no inject action applies (or a different header is injected) a
// client-forged tenant-restriction header would otherwise pass through and impose the client's own tenant
// allowlist upstream.
var enterpriseControlledRequestHeaders = []string{
	GoogleWorkspaceTenantRestrictionHeader,
	Microsoft365TenantRestrictionHeader,
	"Restrict-Access-Context",
	"chatgpt-allowed-workspace-id",
	"anthropic-allowed-org-ids",
}

// StripEnterpriseControlledHeaders removes every enterprise-controlled tenant-restriction header from h.
// Ingress paths that forward client headers upstream must call this (or go through
// RewriteRequestFromDecision, which calls it) regardless of whether an inject action applies.
func StripEnterpriseControlledHeaders(h http.Header) {
	for _, name := range enterpriseControlledRequestHeaders {
		h.Del(name)
	}
}

type HeaderValueResolver interface {
	ResolveHeaderValue(ref string) (string, bool)
}

type HeaderValueMap map[string]string

func (m HeaderValueMap) ResolveHeaderValue(ref string) (string, bool) {
	value, ok := m[ref]
	return value, ok
}

type RewriteResult struct {
	DecisionID                         string
	PolicyID                           string
	SaaSApplicationID                  string
	HeaderName                         string
	HeaderValueRef                     string
	HeaderValueKind                    string
	HeaderValueResolved                bool
	HeaderApplied                      bool
	HeaderValueMaterialLogged          bool
	InjectActionSeen                   bool
	TLSBypassApplied                   bool
	TLSBypassRuleID                    string
	HeaderInjectionSuppressedByBypass  bool
	InspectionRouteCategory            string
	InspectionExecutionScope           string
	EdgeTLSPolicyDecision              string
	RuntimeTLSDecryptionObserved       bool
	RuntimeHeaderInjectionObserved     bool
	NetworkExtensionRuntimeUsed        bool
	LocalHTTPRewriteHarnessObservation bool
	EdgeRuntimeRewritePathObserved     bool
}

type RewriteRequestOptions struct {
	LocalHTTPRewriteHarnessObservation bool
	EdgeRuntimeRewritePathObserved     bool
}

func RewriteRequestFromDecision(r *http.Request, dec model.AccessDecision, resolver HeaderValueResolver) (*http.Request, RewriteResult, error) {
	return RewriteRequestFromDecisionWithOptions(r, dec, resolver, RewriteRequestOptions{LocalHTTPRewriteHarnessObservation: true})
}

func RewriteRequestFromDecisionWithOptions(r *http.Request, dec model.AccessDecision, resolver HeaderValueResolver, opts RewriteRequestOptions) (*http.Request, RewriteResult, error) {
	if r == nil {
		return nil, RewriteResult{}, fmt.Errorf("http request is required")
	}
	result := RewriteResult{
		DecisionID:                         dec.ID,
		PolicyID:                           dec.PolicyID,
		SaaSApplicationID:                  saasApplicationID(dec),
		HeaderName:                         stringMetadata(dec.Metadata, "swg_tenant_restriction_header_name"),
		HeaderValueRef:                     stringMetadata(dec.Metadata, "swg_tenant_restriction_header_value_ref"),
		HeaderValueKind:                    stringMetadata(dec.Metadata, "swg_tenant_restriction_header_value_kind"),
		TLSBypassApplied:                   boolMetadata(dec.Metadata, "swg_tls_bypass_applied"),
		TLSBypassRuleID:                    stringMetadata(dec.Metadata, "swg_tls_bypass_rule_id"),
		HeaderInjectionSuppressedByBypass:  boolMetadata(dec.Metadata, "swg_tenant_restriction_header_injection_suppressed_by_bypass"),
		InspectionRouteCategory:            stringPtrValue(dec.InspectionRouteCategory),
		InspectionExecutionScope:           stringPtrValue(dec.InspectionExecutionScope),
		EdgeTLSPolicyDecision:              stringMetadata(dec.Metadata, "edge_tls_policy_decision"),
		RuntimeTLSDecryptionObserved:       boolMetadata(dec.Metadata, "swg_tls_runtime_decryption_observed"),
		RuntimeHeaderInjectionObserved:     boolMetadata(dec.Metadata, "swg_header_injection_runtime_observed"),
		NetworkExtensionRuntimeUsed:        boolMetadata(dec.Metadata, "network_extension_runtime_used"),
		LocalHTTPRewriteHarnessObservation: opts.LocalHTTPRewriteHarnessObservation,
		EdgeRuntimeRewritePathObserved:     opts.EdgeRuntimeRewritePathObserved,
	}

	rewritten := r.Clone(r.Context())
	rewritten.Header = r.Header.Clone()
	// Unconditional: a client-forged tenant-restriction header must die here even when no inject action
	// applies to this request (the injection below Sets only the one policy-selected header).
	StripEnterpriseControlledHeaders(rewritten.Header)

	action, ok, err := injectAction(dec.Actions)
	if err != nil {
		return nil, result, err
	}
	if !ok {
		return rewritten, result, nil
	}

	result.InjectActionSeen = true
	headerName := strings.TrimSpace(stringMetadata(action.Metadata, "header_name"))
	headerValueRef := strings.TrimSpace(stringMetadata(action.Metadata, "header_value_ref"))
	headerValueKind := strings.TrimSpace(stringMetadata(action.Metadata, "header_value_kind"))
	if headerName == "" {
		return nil, result, fmt.Errorf("tenant header action missing header_name")
	}
	if headerValueRef == "" || !strings.HasPrefix(headerValueRef, "operator_config_ref:") {
		return nil, result, fmt.Errorf("tenant header action has invalid header_value_ref")
	}
	if resolver == nil {
		return nil, result, fmt.Errorf("tenant header value resolver is required")
	}
	value, ok := resolver.ResolveHeaderValue(headerValueRef)
	if !ok || strings.TrimSpace(value) == "" {
		return nil, result, fmt.Errorf("tenant header value ref %s is not configured", headerValueRef)
	}

	// The M365 context travels with the same action and resolver snapshot as the allowlist.
	// Resolve both BEFORE exposing a rewritten request to the forwarding path.
	if ref := stringMetadata(action.Metadata, "restriction_context_ref"); ref != "" {
		if !strings.EqualFold(headerName, Microsoft365TenantRestrictionHeader) || !strings.HasPrefix(ref, "operator_config_ref:") {
			return nil, result, fmt.Errorf("invalid restriction context reference")
		}
		context, ok := resolver.ResolveHeaderValue(ref)
		if !ok || strings.TrimSpace(context) == "" || strings.ContainsAny(context, "\r\n") {
			return nil, result, fmt.Errorf("restriction context is not configured")
		}
		rewritten.Header.Set("Restrict-Access-Context", context)
	}
	rewritten.Header.Set(headerName, value)
	result.HeaderName = headerName
	result.HeaderValueRef = headerValueRef
	result.HeaderValueKind = headerValueKind
	result.HeaderValueResolved = true
	result.HeaderApplied = true
	result.HeaderValueMaterialLogged = false
	return rewritten, result, nil
}

func injectAction(actions []model.DecisionAction) (model.DecisionAction, bool, error) {
	var found model.DecisionAction
	for _, action := range actions {
		if action.Type != injectTenantRestrictionHeaderAction {
			continue
		}
		if _, ok := action.Metadata["header_value"]; ok {
			return model.DecisionAction{}, false, fmt.Errorf("tenant header action included value material")
		}
		if found.Type != "" {
			return model.DecisionAction{}, false, fmt.Errorf("multiple tenant header inject actions are not supported")
		}
		found = action
	}
	return found, found.Type != "", nil
}

func saasApplicationID(dec model.AccessDecision) string {
	if dec.SaaSContext == nil {
		return ""
	}
	return dec.SaaSContext.SaaSApplicationID
}

func stringMetadata(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return value
}

func boolMetadata(metadata map[string]any, key string) bool {
	if metadata == nil {
		return false
	}
	value, _ := metadata[key].(bool)
	return value
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
