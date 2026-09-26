package swg

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/policy"
	"os"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantrestriction"
)

// SWG tenant-restriction config exposed read-only via the Admin API. Surfaces the current
// (previously startup-flag / file-driven) SWG tenant-restriction state on the Admin Policy API.
// Non-secret only — the header-value material (allowed-domains etc.) is never included.

type adminSWGTenantRestrictionRuleStatus struct {
	ID                 string `json:"id"`
	Managed            bool   `json:"managed,omitempty"`
	ConfigurationSaved bool   `json:"configuration_saved"`
	ValueConfigured    bool   `json:"value_configured"`
	ContextConfigured  bool   `json:"context_configured"`
	// TenantID is the organization the rule belongs to. Empty means it applies to every request this node
	// serves, which is why an empty one stays visible to everybody: it affects them.
	TenantID          string `json:"tenant_id,omitempty"`
	SaaSApplicationID string `json:"saas_application_id"`
	Provider          string `json:"provider"`
	HeaderName        string `json:"header_name"`
	HeaderValueRef    string `json:"header_value_ref"`
	HeaderValueKind   string `json:"header_value_kind"`
	EnforcementMode   string `json:"enforcement_mode"`
	Status            string `json:"status"`
	Active            bool   `json:"active"`
}

type TenantRestrictionStatusResponse struct {
	SchemaVersion                       string                                `json:"schema_version"`
	TenantID                            string                                `json:"tenant_id"`
	ResolverConfigured                  bool                                  `json:"tenant_restriction_resolver_configured"`
	OperatorConfigRefs                  []string                              `json:"operator_config_refs"`
	HeaderValueInDecision               bool                                  `json:"tenant_restriction_header_value_in_decision"`
	ActiveRuleCount                     int                                   `json:"active_rule_count"`
	RuleCount                           int                                   `json:"rule_count"`
	Rules                               []adminSWGTenantRestrictionRuleStatus `json:"rules"`
	OperatorConfigValueMaterialInStatus bool                                  `json:"operator_config_value_material_in_status"`
	NoSecretAttestation                 bool                                  `json:"no_secret_attestation"`
}

// TenantRestrictionStatus summarizes the live SWG tenant-restriction runtime config + the bundle's
// tenant-restriction rules into a non-secret status. Header-value material is never emitted.
func TenantRestrictionStatus(swgRuntime RuntimeConfig, bundle model.PolicyBundle) TenantRestrictionStatusResponse {
	rules := make([]adminSWGTenantRestrictionRuleStatus, 0, len(bundle.SWGTenantRestrictionRules))
	activeCount := 0
	for _, rule := range bundle.SWGTenantRestrictionRules {
		active := strings.EqualFold(strings.TrimSpace(rule.Status), "active")
		if active {
			activeCount++
		}
		rules = append(rules, adminSWGTenantRestrictionRuleStatus{
			ID:                rule.ID,
			TenantID:          rule.TenantID,
			SaaSApplicationID: rule.SaaSApplicationID,
			Provider:          rule.Provider,
			HeaderName:        rule.HeaderName,
			HeaderValueRef:    rule.HeaderValueRef,
			HeaderValueKind:   rule.HeaderValueKind,
			EnforcementMode:   rule.EnforcementMode,
			Status:            rule.Status,
			Active:            active,
		})
	}
	refs := append([]string(nil), swgRuntime.TenantRestrictionOperatorConfigRefs...)
	if refs == nil {
		refs = []string{}
	}
	return TenantRestrictionStatusResponse{
		SchemaVersion:                       "admin_swg_tenant_restriction_status.v1",
		TenantID:                            bundle.TenantID,
		ResolverConfigured:                  swgRuntime.TenantRestrictionResolverConfigured,
		OperatorConfigRefs:                  refs,
		HeaderValueInDecision:               swgRuntime.TenantRestrictionHeaderValueInDecision,
		ActiveRuleCount:                     activeCount,
		RuleCount:                           len(rules),
		Rules:                               rules,
		OperatorConfigValueMaterialInStatus: false,
		NoSecretAttestation:                 true,
	}
}

// --- write path: hot-apply tenant restriction header values via Admin API ---

type TenantRestrictionUpdateRequest struct {
	// HeaderValueUpdates maps operator_config_ref:* -> new non-secret header value (allowed-domains,
	// allowed-tenant-ids, etc.). Only already-configured active refs may be updated.
	HeaderValueUpdates map[string]string `json:"header_value_updates"`
	// SaaSEnablement maps saas_application_id -> desired enabled state (true=active, false=inactive).
	// Enables/disables tenant-restriction enforcement for the SaaS on the live decision path (hot-apply).
	// Enabling is only allowed when the rule's header value is already resolvable (configured at startup).
	SaaSEnablement map[string]bool `json:"saas_enablement"`
}

// adminSWGTenantRestrictionToggleStore is the runtime rule-status override surface (implemented by
// *policy.Store). The Admin handler type-asserts the policy store to it for SaaS enable/disable.
type adminSWGTenantRestrictionToggleStore interface {
	SetTenantRestrictionRuleStatusesContext(context.Context, map[string]string) error
	TenantRestrictionRuleStatusOverrides() map[string]string
}

// effectiveTenantRestrictionRules applies status overrides to a copy of the bundle rules (for status
// display and the post-toggle response), never mutating the shared base bundle.
func effectiveTenantRestrictionRules(rules []model.SWGTenantRestrictionRule, overrides map[string]string) []model.SWGTenantRestrictionRule {
	if len(overrides) == 0 {
		return rules
	}
	out := make([]model.SWGTenantRestrictionRule, len(rules))
	copy(out, rules)
	for i := range out {
		if status, ok := overrides[out[i].ID]; ok {
			out[i].Status = status
		}
	}
	return out
}

type adminSWGTenantRestrictionAppliedRef struct {
	Ref string `json:"ref"`
	// ValueFingerprint is a non-secret proof that the live request-path resolver now serves the new
	// value (re-read from the shared resolver after the atomic swap). The raw value is never returned.
	ValueFingerprint string `json:"value_fingerprint"`
}

type TenantRestrictionUpdateResponse struct {
	SchemaVersion             string                                 `json:"schema_version"`
	AppliedRefs               []adminSWGTenantRestrictionAppliedRef  `json:"applied_refs"`
	AppliedSaaS               []adminSWGTenantRestrictionAppliedSaaS `json:"applied_saas"`
	HotApplied                bool                                   `json:"hot_applied"`
	PersistedToOperatorConfig bool                                   `json:"persisted_to_operator_config"`
	PersistedToValueStore     bool                                   `json:"persisted_to_value_store"`
	NoSecretAttestation       bool                                   `json:"no_secret_attestation"`
	Status                    TenantRestrictionStatusResponse        `json:"status"`
}

// nonSecretValueFingerprint returns a non-secret fingerprint (length + short sha256) used as proof
// that a value was applied, without exposing the value material.
func nonSecretValueFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("len_%d_sha256_%x", len(value), sum[:4])
}

// adminSWGTenantRestrictionAppliedSaaS records a SaaS enable/disable toggle applied to the live
// decision path (runtime rule-status override).
type adminSWGTenantRestrictionAppliedSaaS struct {
	SaaSApplicationID string `json:"saas_application_id"`
	RuleID            string `json:"rule_id"`
	Status            string `json:"status"`
}

// ApplyTenantRestrictionUpdate hot-applies (a) operator header value updates to the live SWG
// resolver and (b) SaaS enable/disable toggles via the policy store runtime rule-status override.
// Both take effect on the live request path with no restart. Header value writes also persist to the
// operator config + durable value store. Non-secret only; raw values never returned.
func ApplyTenantRestrictionUpdate(swgRuntime RuntimeConfig, baseBundle model.PolicyBundle, policyStore policy.RuntimeStore, req TenantRestrictionUpdateRequest) (TenantRestrictionUpdateResponse, error) {
	return ApplyTenantRestrictionUpdateContext(context.Background(), swgRuntime, baseBundle, policyStore, req)
}

func ApplyTenantRestrictionUpdateContext(ctx context.Context, swgRuntime RuntimeConfig, baseBundle model.PolicyBundle, policyStore policy.RuntimeStore, req TenantRestrictionUpdateRequest) (TenantRestrictionUpdateResponse, error) {
	if len(req.HeaderValueUpdates) == 0 && len(req.SaaSEnablement) == 0 {
		return TenantRestrictionUpdateResponse{}, fmt.Errorf("no header_value_updates or saas_enablement provided")
	}

	// (a) header value updates -> resolver hot-swap.
	appliedRefs := make([]adminSWGTenantRestrictionAppliedRef, 0)
	if len(req.HeaderValueUpdates) > 0 {
		if !swgRuntime.TenantRestrictionResolverConfigured {
			return TenantRestrictionUpdateResponse{}, fmt.Errorf("tenant restriction is not configured; no active refs to update")
		}
		applied, err := swgRuntime.TenantRestrictionResolver.ReplaceHeaderValues(req.HeaderValueUpdates)
		if err != nil {
			return TenantRestrictionUpdateResponse{}, err
		}
		for _, ref := range applied {
			value, ok := swgRuntime.TenantRestrictionResolver.ResolveHeaderValue(ref)
			if !ok {
				return TenantRestrictionUpdateResponse{}, fmt.Errorf("ref %s did not resolve after apply", ref)
			}
			appliedRefs = append(appliedRefs, adminSWGTenantRestrictionAppliedRef{Ref: ref, ValueFingerprint: nonSecretValueFingerprint(value)})
		}
	}

	// (b) SaaS enable/disable -> runtime rule-status override on the policy store.
	appliedSaaS := make([]adminSWGTenantRestrictionAppliedSaaS, 0)
	if len(req.SaaSEnablement) > 0 {
		toggleStore, ok := policyStore.(adminSWGTenantRestrictionToggleStore)
		if !ok {
			return TenantRestrictionUpdateResponse{}, fmt.Errorf("policy store does not support saas enable/disable")
		}
		statuses := map[string]string{}
		for saas, enabled := range req.SaaSEnablement {
			saas = strings.TrimSpace(saas)
			matched := false
			for _, rule := range baseBundle.SWGTenantRestrictionRules {
				if rule.SaaSApplicationID != saas {
					continue
				}
				matched = true
				status := "inactive"
				if enabled {
					// Enabling requires the rule's header value to be resolvable (configured at startup).
					if _, ok := swgRuntime.TenantRestrictionResolver.ResolveHeaderValue(rule.HeaderValueRef); !ok {
						return TenantRestrictionUpdateResponse{}, fmt.Errorf("cannot enable %s: header value for %s is not configured (set it first via header_value_updates / start with it active)", saas, rule.HeaderValueRef)
					}
					status = "active"
				}
				statuses[rule.ID] = status
				appliedSaaS = append(appliedSaaS, adminSWGTenantRestrictionAppliedSaaS{SaaSApplicationID: saas, RuleID: rule.ID, Status: status})
			}
			if !matched {
				return TenantRestrictionUpdateResponse{}, fmt.Errorf("saas %s has no tenant restriction rule", saas)
			}
		}
		if err := toggleStore.SetTenantRestrictionRuleStatusesContext(ctx, statuses); err != nil {
			return TenantRestrictionUpdateResponse{}, err
		}
	}

	// Persist header value updates to the active operator config + durable value store (cross-restart).
	persistedActive := false
	persistedStore := false
	if len(req.HeaderValueUpdates) > 0 {
		if path := strings.TrimSpace(swgRuntime.TenantRestrictionOperatorConfigPath); path != "" {
			if perr := persistOperatorConfigHeaderValues(path, req.HeaderValueUpdates); perr == nil {
				persistedActive = true
			}
		}
		if path := strings.TrimSpace(swgRuntime.TenantRestrictionOperatorValueStorePath); path != "" {
			if perr := persistOperatorConfigHeaderValues(path, req.HeaderValueUpdates); perr == nil {
				persistedStore = true
			}
		}
	}

	// Status reflects the live runtime-effective rules (base bundle + current overrides).
	effectiveBundle := baseBundle
	if toggleStore, ok := policyStore.(adminSWGTenantRestrictionToggleStore); ok {
		effectiveBundle.SWGTenantRestrictionRules = effectiveTenantRestrictionRules(baseBundle.SWGTenantRestrictionRules, toggleStore.TenantRestrictionRuleStatusOverrides())
	}
	return TenantRestrictionUpdateResponse{
		SchemaVersion:             "admin_swg_tenant_restriction_update.v1",
		AppliedRefs:               appliedRefs,
		AppliedSaaS:               appliedSaaS,
		HotApplied:                true,
		PersistedToOperatorConfig: persistedActive,
		PersistedToValueStore:     persistedStore,
		NoSecretAttestation:       true,
		Status:                    TenantRestrictionStatus(swgRuntime, effectiveBundle),
	}, nil
}

// persistOperatorConfigHeaderValues best-effort updates the operator config file's header_values[].value
// for the given refs so the running edge's on-disk config stays consistent with the hot-applied state.
// (Cross-dataplane-restart persistence additionally needs the dataplane value store; tracked as follow-up.)
func persistOperatorConfigHeaderValues(path string, updates map[string]string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	entries, ok := doc["header_values"].([]any)
	if !ok {
		return fmt.Errorf("operator config has no header_values array")
	}
	for _, e := range entries {
		entry, ok := e.(map[string]any)
		if !ok {
			continue
		}
		ref, _ := entry["ref"].(string)
		if newValue, found := updates[strings.TrimSpace(ref)]; found {
			entry["value"] = strings.TrimSpace(newValue)
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o600)
}

// ForTenant narrows a status to what one organization's administrator may be told.
//
// ★★★ WHY (2026-08-16, measured). A node runs ONE runtime policy bundle, and this status was served to
// whoever asked: a customer's SaaS Tenant Restriction screen listed another organization's rules — header
// names, operator config refs and all — as if they were the caller's own.
//
// A rule carrying NO organization stays visible: it applies to every request the node serves, so it applies to
// the caller too, and hiding it would tell a customer their traffic is unrestricted while it is being
// restricted. The counts are recomputed from what survives, because a total that counts rows the reader cannot
// see is a number about somebody else. The bundle's own tenant id is replaced by the caller's: it named which
// other organization the node belongs to.
//
// callerTenant == "" with keepAll == false yields only unattributed rules, which is the correct answer for a
// caller whose organization cannot be resolved.
func (s TenantRestrictionStatusResponse) ForTenant(callerTenant string, keepAll bool) TenantRestrictionStatusResponse {
	if keepAll {
		return s
	}
	kept := make([]adminSWGTenantRestrictionRuleStatus, 0, len(s.Rules))
	active := 0
	for _, rule := range s.Rules {
		if !tenantRestrictionRuleVisible(rule.TenantID, callerTenant) {
			continue
		}
		if rule.Active {
			active++
		}
		kept = append(kept, rule)
	}
	s.Rules = kept
	s.RuleCount = len(kept)
	s.ActiveRuleCount = active
	s.TenantID = callerTenant
	return s
}

// UpdateRefusal names the first thing in an update the caller may not touch, or "" when everything referenced
// is theirs. Checked BEFORE applying: a partial apply followed by an error would leave another organization's
// enforcement changed AND report failure, which is the worst of both.
func (s TenantRestrictionStatusResponse) UpdateRefusal(req TenantRestrictionUpdateRequest, callerTenant string, keepAll bool) string {
	if keepAll {
		return ""
	}
	for saasID := range req.SaaSEnablement {
		for _, rule := range s.Rules {
			if !strings.EqualFold(strings.TrimSpace(rule.SaaSApplicationID), strings.TrimSpace(saasID)) {
				continue
			}
			if !tenantRestrictionRuleVisible(rule.TenantID, callerTenant) {
				return saasID
			}
		}
	}
	// A header value ref is configuration shared by whatever rules cite it. A caller who owns none of the
	// citing rules must not be able to replace the value every one of them injects.
	for ref := range req.HeaderValueUpdates {
		owned, cited := false, false
		for _, rule := range s.Rules {
			if !strings.EqualFold(strings.TrimSpace(rule.HeaderValueRef), strings.TrimSpace(ref)) {
				continue
			}
			cited = true
			if tenantRestrictionRuleVisible(rule.TenantID, callerTenant) {
				owned = true
			}
		}
		if cited && !owned {
			return ref
		}
	}
	return ""
}

func tenantRestrictionRuleVisible(ruleTenant, callerTenant string) bool {
	owner := strings.TrimSpace(ruleTenant)
	return owner == "" || strings.EqualFold(owner, strings.TrimSpace(callerTenant))
}

// WithManagedProviders fills the built-in catalog for a new organization while
// preserving existing startup-file rules and their legacy editing contract.
func (s TenantRestrictionStatusResponse) WithManagedProviders(tenant string, settings map[string]tenantrestriction.Setting) TenantRestrictionStatusResponse {
	if tenant == "" {
		return s
	}
	seen := map[string]bool{}
	for i, r := range s.Rules {
		seen[r.Provider] = true
		if r.HeaderValueRef == tenantrestriction.Ref(tenant, r.Provider) {
			v, saved := settings[r.Provider]
			s.Rules[i].ConfigurationSaved = saved
			s.Rules[i].Managed = true
			s.Rules[i].ValueConfigured = v.AllowedValue != ""
			s.Rules[i].ContextConfigured = v.ContextTenantID != ""
		}
	}
	for _, p := range tenantrestriction.Providers() {
		if seen[p.ID] {
			continue
		}
		_, saved := settings[p.ID]
		r := tenantrestriction.Rule(tenant, p, settings[p.ID])
		s.Rules = append(s.Rules, adminSWGTenantRestrictionRuleStatus{ID: r.ID, TenantID: tenant, SaaSApplicationID: p.AppID, Provider: p.ID, HeaderName: p.Header, HeaderValueRef: r.HeaderValueRef, HeaderValueKind: p.Kind, EnforcementMode: r.EnforcementMode, Status: r.Status, Active: settings[p.ID].Enabled, Managed: true, ConfigurationSaved: saved, ValueConfigured: settings[p.ID].AllowedValue != "", ContextConfigured: settings[p.ID].ContextTenantID != ""})
	}
	s.RuleCount = len(s.Rules)
	s.ActiveRuleCount = 0
	for _, r := range s.Rules {
		if r.Active {
			s.ActiveRuleCount++
		}
	}
	s.ResolverConfigured = true
	return s
}
