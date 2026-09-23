package swg

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/policy"
	"os"
	"strings"
	"sync"

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

// Legacy updates span files, a resolver and runtime policy. Expose confirmed
// stages when a later stage fails; never imply rollback of earlier saves.
type TenantRestrictionUpdateError struct {
	Stage   string
	Outcome TenantRestrictionUpdateResponse
}

func (e *TenantRestrictionUpdateError) Error() string {
	return "Tenant restriction saving could not be confirmed; some settings may have changed. Reload and retry."
}

var legacyRestrictionWriteMu sync.Mutex

func ApplyTenantRestrictionUpdateContext(ctx context.Context, runtime RuntimeConfig, bundle model.PolicyBundle, store policy.RuntimeStore, req TenantRestrictionUpdateRequest) (TenantRestrictionUpdateResponse, error) {
	legacyRestrictionWriteMu.Lock()
	defer legacyRestrictionWriteMu.Unlock()
	resp := TenantRestrictionUpdateResponse{SchemaVersion: "admin_swg_tenant_restriction_update.v1", NoSecretAttestation: true, AppliedRefs: []adminSWGTenantRestrictionAppliedRef{}, AppliedSaaS: []adminSWGTenantRestrictionAppliedSaaS{}}
	fail := func(stage string) (TenantRestrictionUpdateResponse, error) {
		return resp, &TenantRestrictionUpdateError{Stage: stage, Outcome: resp}
	}
	if ctx.Err() != nil {
		return fail("request")
	}
	if len(req.HeaderValueUpdates) == 0 && len(req.SaaSEnablement) == 0 {
		return resp, fmt.Errorf("no header_value_updates or saas_enablement provided")
	}
	// Validate the complete request before changing any resource.
	updates := map[string]string{}
	for ref, value := range req.HeaderValueUpdates {
		ref, value = strings.TrimSpace(ref), strings.TrimSpace(value)
		if !runtime.TenantRestrictionResolverConfigured {
			return resp, fmt.Errorf("tenant restriction is not configured")
		}
		if _, ok := runtime.TenantRestrictionResolver.ResolveHeaderValue(ref); !ok || value == "" {
			return resp, fmt.Errorf("invalid tenant restriction reference or empty value")
		}
		if _, duplicate := updates[ref]; duplicate {
			return resp, fmt.Errorf("duplicate tenant restriction reference")
		}
		updates[ref] = value
	}
	toggle, ok := store.(adminSWGTenantRestrictionToggleStore)
	statuses := map[string]string{}
	applied := []adminSWGTenantRestrictionAppliedSaaS{}
	if len(req.SaaSEnablement) > 0 && !ok {
		return resp, fmt.Errorf("policy store does not support saas enable/disable")
	}
	for saas, enabled := range req.SaaSEnablement {
		saas = strings.TrimSpace(saas)
		matched := false
		for _, rule := range bundle.SWGTenantRestrictionRules {
			if rule.SaaSApplicationID != saas {
				continue
			}
			matched = true
			status := "inactive"
			if enabled {
				if _, found := runtime.TenantRestrictionResolver.ResolveHeaderValue(rule.HeaderValueRef); !found {
					return resp, fmt.Errorf("configure the header value before enabling this application")
				}
				status = "active"
			}
			statuses[rule.ID] = status
			applied = append(applied, adminSWGTenantRestrictionAppliedSaaS{SaaSApplicationID: saas, RuleID: rule.ID, Status: status})
		}
		if !matched {
			return resp, fmt.Errorf("application has no tenant restriction rule")
		}
	}
	type pendingFile struct {
		path     string
		raw      []byte
		operator bool
	}
	files := []pendingFile{}
	if len(updates) > 0 {
		for i, path := range []string{runtime.TenantRestrictionOperatorConfigPath, runtime.TenantRestrictionOperatorValueStorePath} {
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}
			raw, err := prepareOperatorConfigHeaderValues(path, updates)
			if err != nil {
				return fail("header_file_prepare")
			}
			files = append(files, pendingFile{path: path, raw: raw, operator: i == 0})
		}
		if len(files) == 0 {
			return fail("header_storage_unconfigured")
		}
		for _, file := range files {
			if ctx.Err() != nil {
				return fail("request")
			}
			if err := (blobstore.FilePersister{Path: file.path}).Save(file.raw); err != nil {
				return fail("header_file_save")
			}
			if file.operator {
				resp.PersistedToOperatorConfig = true
			} else {
				resp.PersistedToValueStore = true
			}
		}
		if ctx.Err() != nil {
			return fail("request")
		}
		refs, err := runtime.TenantRestrictionResolver.ReplaceHeaderValues(updates)
		if err != nil {
			return fail("header_live_apply")
		}
		for _, ref := range refs {
			resp.AppliedRefs = append(resp.AppliedRefs, adminSWGTenantRestrictionAppliedRef{Ref: ref, ValueFingerprint: nonSecretValueFingerprint(updates[ref])})
		}
	}
	if len(statuses) > 0 {
		if ctx.Err() != nil {
			return fail("request")
		}
		if err := toggle.SetTenantRestrictionRuleStatusesContext(ctx, statuses); err != nil {
			return fail("runtime_status_save")
		}
		resp.AppliedSaaS = applied
	}
	resp.HotApplied = true
	effective := bundle
	if ok {
		effective.SWGTenantRestrictionRules = effectiveTenantRestrictionRules(bundle.SWGTenantRestrictionRules, toggle.TenantRestrictionRuleStatusOverrides())
	}
	resp.Status = TenantRestrictionStatus(runtime, effective)
	return resp, nil
}

// A missing/duplicate ref must not turn a no-op into confirmed persistence.
func prepareOperatorConfigHeaderValues(path string, updates map[string]string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	entries, ok := doc["header_values"].([]any)
	if !ok {
		return nil, fmt.Errorf("operator config has no header_values array")
	}
	found := map[string]bool{}
	for _, e := range entries {
		entry, ok := e.(map[string]any)
		if !ok {
			continue
		}
		ref, _ := entry["ref"].(string)
		ref = strings.TrimSpace(ref)
		if value, exists := updates[ref]; exists {
			if found[ref] {
				return nil, fmt.Errorf("duplicate operator reference")
			}
			entry["value"] = value
			found[ref] = true
		}
	}
	if len(found) != len(updates) {
		return nil, fmt.Errorf("operator config is missing requested references")
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
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
