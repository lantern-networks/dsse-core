package main

import (
	"net/http"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
)

// catalogGroupView is one built-in SaaS catalog group presented as an endpoint group: a named host set on the
// decrypt or bypass axis. Phase A of the unified policy model surfaces the catalog as built-in endpoint groups.
type catalogGroupView struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Axis        string   `json:"axis"` // decrypt | bypass
	Description string   `json:"description"`
	Patterns    []string `json:"patterns"`
}

// catalogGroups returns the built-in SaaS catalog as endpoint-group views (decrypt + bypass axes).
func catalogGroups() []catalogGroupView {
	out := []catalogGroupView{}
	for _, g := range inspectionposture.AuthDecryptGroups {
		out = append(out, catalogGroupView{Name: g.Name, Category: g.Category, Axis: "decrypt", Description: g.Description, Patterns: g.Patterns})
	}
	for _, g := range inspectionposture.SaaSBypassGroups {
		out = append(out, catalogGroupView{Name: g.Name, Category: g.Category, Axis: "bypass", Description: g.Description, Patterns: g.Patterns})
	}
	return out
}

// inspectionPostureSnapshot gathers the live posture view: the configured posture plus the engine's actual
// intercept + bypass sets. Used by both the GET and POST handlers.
func inspectionPostureSnapshot(config serverConfig) inspectionPostureResponse {
	posture := inspectionposture.DefaultPosture()
	if config.InspectionPosture != nil {
		posture = config.InspectionPosture()
	}
	var interceptHosts, effectiveBypass []string
	if config.NetworkExtensionLabTLS != nil {
		interceptHosts = config.NetworkExtensionLabTLS.InterceptHosts()
		effectiveBypass = config.NetworkExtensionLabTLS.BypassHosts()
	}
	return buildInspectionPosture(posture, interceptHosts, effectiveBypass, knownbypass.Groups)
}

// knownBypassGroupView is one curated known-bypass group made visible to the operator, with whether it is
// currently active in the live bypass set. The curated list is hardcoded (knownbypass.Groups); showing it here
// is the "make the hidden default visible" half of docs/invisible_effective_configuration.md.
type knownBypassGroupView struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Patterns    []string `json:"patterns"`
	Active      bool     `json:"active"`
}

// authDecryptGroupView is one curated SaaS sign-in group worth decrypting under bypass-default, with whether it
// is currently in the decrypt allowlist. Selecting it keeps tenant restriction working even when the default is
// bypass (the auth=Inspect preset).
type authDecryptGroupView struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Patterns    []string `json:"patterns"`
	Selected    bool     `json:"selected"`
}

// inspectionPostureResponse surfaces the default inspection posture: the deployment mode (decrypt_all vs
// bypass_default), the decrypt allowlist (explicit hosts + selected SaaS auth groups) and the curated
// known-bypass list, plus the live intercept/bypass sets the engine actually applies.
type inspectionPostureResponse struct {
	TenantID         string `json:"tenant_id"`
	Scope            string `json:"scope"`
	Configurable     bool   `json:"configurable"`
	RuntimeAvailable bool   `json:"runtime_available"`
	CanManageRules   bool   `json:"can_manage_rules"`

	DefaultMode            string                 `json:"default_mode"`     // decrypt_all | bypass_default
	InterceptHosts         []string               `json:"intercept_hosts"`  // live engine intercept set ("*" = decrypt-all)
	EffectiveBypass        []string               `json:"effective_bypass"` // live engine raw-forward set
	KnownBypassEnabled     bool                   `json:"known_bypass_enabled"`
	DecryptAllowlistHosts  []string               `json:"decrypt_allowlist_hosts"`
	DecryptAllowlistGroups []string               `json:"decrypt_allowlist_groups"`
	BypassGroups           []string               `json:"bypass_groups"`       // enabled SaaS Optimize bypass groups
	AuthDecryptGroups      []authDecryptGroupView `json:"auth_decrypt_groups"` // available SaaS sign-in presets
	SaaSBypassGroups       []authDecryptGroupView `json:"saas_bypass_groups"`  // available SaaS Optimize bypass presets
	KnownBypassGroups      []knownBypassGroupView `json:"known_bypass_groups"`
	Warnings               []string               `json:"warnings,omitempty"` // safety guidance (e.g. tenant restriction at risk)
	Note                   string                 `json:"note"`
}

// anyPatternPresent reports whether any pattern is present (normalized) in set.
func anyPatternPresent(patterns, set []string) bool {
	present := make(map[string]bool, len(set))
	for _, s := range set {
		present[strings.ToLower(strings.TrimSpace(s))] = true
	}
	for _, p := range patterns {
		if present[strings.ToLower(strings.TrimSpace(p))] {
			return true
		}
	}
	return false
}

// patternsAllPresent reports whether every pattern is present (normalized, case-insensitive) in set — used to
// mark a known-bypass group "active" when the engine has folded its patterns into the live bypass set.
func patternsAllPresent(patterns, set []string) bool {
	if len(patterns) == 0 {
		return false
	}
	present := make(map[string]bool, len(set))
	for _, s := range set {
		present[strings.ToLower(strings.TrimSpace(s))] = true
	}
	for _, p := range patterns {
		if !present[strings.ToLower(strings.TrimSpace(p))] {
			return false
		}
	}
	return true
}

func stringInSetFold(s string, set []string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, v := range set {
		if strings.ToLower(strings.TrimSpace(v)) == s {
			return true
		}
	}
	return false
}

// buildInspectionPosture assembles the posture view from the configured posture, the engine's live intercept +
// bypass sets, and the curated known-bypass groups. Read-only.
func buildInspectionPosture(p inspectionposture.Posture, interceptHosts, effectiveBypass []string, knownGroups []knownbypass.Group) inspectionPostureResponse {
	mode := p.Mode
	if mode != inspectionposture.ModeBypassDefault {
		mode = inspectionposture.ModeDecryptAll
	}
	knownViews := make([]knownBypassGroupView, 0, len(knownGroups))
	for _, g := range knownGroups {
		knownViews = append(knownViews, knownBypassGroupView{
			Name:        g.Name,
			Description: g.Description,
			Patterns:    g.Patterns,
			Active:      patternsAllPresent(g.Patterns, effectiveBypass),
		})
	}
	authViews := make([]authDecryptGroupView, 0, len(inspectionposture.AuthDecryptGroups))
	for _, g := range inspectionposture.AuthDecryptGroups {
		authViews = append(authViews, authDecryptGroupView{
			Name:        g.Name,
			Category:    g.Category,
			Description: g.Description,
			Patterns:    g.Patterns,
			Selected:    stringInSetFold(g.Name, p.DecryptAllowlistGroups),
		})
	}
	bypassGroupViews := make([]authDecryptGroupView, 0, len(inspectionposture.SaaSBypassGroups))
	for _, g := range inspectionposture.SaaSBypassGroups {
		bypassGroupViews = append(bypassGroupViews, authDecryptGroupView{
			Name:        g.Name,
			Category:    g.Category,
			Description: g.Description,
			Patterns:    g.Patterns,
			Selected:    stringInSetFold(g.Name, p.BypassGroups),
		})
	}
	var warnings []string
	if mode == inspectionposture.ModeBypassDefault && !anyPatternPresent(inspectionposture.AuthDecryptPatterns(), interceptHosts) {
		warnings = append(warnings, "bypass_default is decrypting no SaaS sign-in host — tenant restriction (header injection on login.* / accounts.*) will NOT work. Select a SaaS sign-in preset (m365_auth/google_auth/…) or add the sign-in hosts to the decrypt allowlist.")
	}
	return inspectionPostureResponse{
		DefaultMode:            mode,
		InterceptHosts:         interceptHosts,
		Warnings:               warnings,
		EffectiveBypass:        effectiveBypass,
		KnownBypassEnabled:     p.KnownBypassEnabled,
		DecryptAllowlistHosts:  p.DecryptAllowlistHosts,
		DecryptAllowlistGroups: p.DecryptAllowlistGroups,
		BypassGroups:           p.BypassGroups,
		AuthDecryptGroups:      authViews,
		SaaSBypassGroups:       bypassGroupViews,
		KnownBypassGroups:      knownViews,
		Note:                   "decrypt_all decrypts every steered HTTPS flow EXCEPT the bypass set; bypass_default decrypts ONLY the allowlist (hosts + selected SaaS auth groups) and raw-forwards the rest. A bypassed flow is still steered and policy-gated. Keep a SaaS auth group selected under bypass_default to keep tenant restriction working.",
	}
}

func inspectionPostureMayWrite(r *http.Request) bool {
	return adminCallerIsOperator(r) && strings.TrimSpace(r.Header.Get("X-Operate-Tenant")) == ""
}
func inspectionPostureForRequest(config serverConfig, r *http.Request) inspectionPostureResponse {
	result := inspectionPostureSnapshot(config)
	result.TenantID = adminTenantIDFromRequest(r)
	result.Scope = "deployment"
	writable := true
	if identity, ok := adminIdentityFromRequest(r); ok {
		writable = adminPermissionAllowed(identity.Roles, "admin.policy.write")
	}
	result.Configurable = writable && inspectionPostureMayWrite(r) && config.SetInspectionPosture != nil && config.InspectionPosture != nil && strings.TrimSpace(config.ConfigSourceURL) == ""
	result.RuntimeAvailable = config.NetworkExtensionLabTLS != nil
	result.CanManageRules = writable && strings.TrimSpace(config.ConfigSourceURL) == ""
	return result
}

// Keep saved-state adoption and its engine callback in order for concurrent updates.
func newInspectionPostureSetter(store *inspectionposture.Store, apply func(string)) func(inspectionposture.Posture, string) (inspectionposture.Posture, error) {
	var mu sync.Mutex
	return func(p inspectionposture.Posture, tenant string) (inspectionposture.Posture, error) {
		mu.Lock()
		defer mu.Unlock()
		saved, err := store.Set(p)
		if err == nil && apply != nil {
			apply(tenant)
		}
		return saved, err
	}
}
