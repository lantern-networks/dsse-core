package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// systemBypassFloorPriority is the precedence of system bypass entries (the known-bypass OS/cert floor and
// emitted cert-pin bypass rules). It sits BELOW operator rules (which default to 100) and just ABOVE the
// catch-all default (1000000), so an explicitly authored rule always wins on the ACCESS axis — a cert-pin/floor
// entry must never out-precedence an operator's deny/allow. The INSPECTION (bypass) effect is independent of
// priority anyway (the raw-forward set always wins over the intercept set), so a low access precedence is safe.
const systemBypassFloorPriority = 900000

// effectiveEgressRuleEntry is ONE row of the unified Egress view: every effective egress rule, whatever surface
// it lives on, normalized to the same source → destination : service ⇒ access × inspection shape. An operator
// expects the Egress view to be the single pane for all egress decisions — not just authored rules but also the
// bypass that is scattered across the inspection posture (known-bypass OS/cert floor, SaaS Optimize) and the
// cert-pin approval queue. Each entry is tagged by Kind and carries the capability flags the Console needs to
// render the right control (edit a rule, toggle a policy, toggle the known-bypass floor, or info-only).
type effectiveEgressRuleEntry struct {
	InspectionSourceWarning string `json:"inspection_source_warning,omitempty"`
	Kind                    string `json:"kind"` // authored | builtin_default | known_bypass | optimize_bypass | cert_pin_bypass
	ID                      string `json:"id"`
	Name                    string `json:"name,omitempty"`
	Priority                int    `json:"priority"`
	SourceText              string `json:"source_text"`      // display: "Any" or the resolved subject aliases
	DestText                string `json:"destination_text"` // display: aliases, a group name, or a host/pattern
	ServiceText             string `json:"service_text"`     // "HTTPS"
	Access                  string `json:"access"`           // allow | deny | authenticate
	Inspection              string `json:"inspection"`       // inspect | bypass
	Status                  string `json:"status"`           // active | disabled | off

	Editable    bool             `json:"editable"`               // an authored rule the editor can open
	Deletable   bool             `json:"deletable"`              // an authored rule that can be removed
	ToggleKind  string           `json:"toggle_kind"`            // rule | policy_status | known_bypass_master | none
	PolicyID    string           `json:"policy_id,omitempty"`    // for toggle_kind=policy_status
	Patterns    []string         `json:"patterns,omitempty"`     // for bypass groups: the host patterns this entry raw-forwards
	Detail      string           `json:"detail,omitempty"`       // human note (provenance / why)
	CandidateID string           `json:"candidate_id,omitempty"` // for cert_pin_bypass: the candidate to suppress when revoking
	Rule        *policyrule.Rule `json:"rule,omitempty"`         // for authored entries: the raw rule so the editor can open it
	// DestinationUnresolved: this authored rule names a destination the endpoint catalog does not know, so it
	// compiles to a match-nothing policy and enforces nothing — while still reading as Active.
	DestinationUnresolved bool `json:"destination_unresolved,omitempty"`
}

// certPinBypassRef pairs a materialized cert-pin bypass host with its candidate id, so the Egress view can offer
// a Revoke action (suppress the candidate → the host is re-intercepted) — not just display it read-only.
type certPinBypassRef struct {
	Host        string
	CandidateID string
}

type effectiveEgressRuleListResponse struct {
	Rules []effectiveEgressRuleEntry `json:"rules"`
	Note  string                     `json:"note"`
}

// effectiveEgressInputs is everything the builder needs, gathered by the edge (which owns every surface).
type effectiveEgressInputs struct {
	InspectionSourceWarnings map[string]string
	Eval                     decision.Evaluator
	Tenant                   string
	AuthoredRules            []policyrule.Rule
	AliasByID                map[string]string                    // asset-catalog id -> alias, for authored source/destination display
	KnownGroups              []knownbypass.Group                  // the OS/cert known-bypass floor
	KnownEnabled             bool                                 // the known-bypass master toggle
	EffectiveBypass          []string                             // engine's live raw-forward set, to mark a known group active
	OptimizeLegacy           []inspectionposture.AuthDecryptGroup // SaaS Optimize groups still selected via posture.bypass_groups (pre-B-1)
	CertPinBypasses          []certPinBypassRef                   // admin-approved (materialized) cert-pin bypasses (host + candidate id)
	// AuthoredBypassHosts is the resolved destination set of authored bypass rules (EgressBypassFQDNs). A cert-pin
	// host that now has an authored bypass rule (Phase C) is shown once — as that rule — not also as a derived
	// cert_pin_bypass row, so the unified view does not double-list it.
	AuthoredBypassHosts []string
	// UnresolvedRuleIDs are the authored rules whose destination resolves to NO address for this tenant. The
	// compiler emits a match-nothing sentinel for those and logs "a DENY here is NOT enforcing"; this carries
	// the same fact to the screen, where a rule was showing as Active with no hint that it enforces nothing.
	// See rules_admin.go for how it is computed and the measurement that found it.
	UnresolvedRuleIDs map[string]bool
}

// subjectText renders a list of asset-catalog subject ids (or the Any wildcard) to a display string.
func subjectText(ids []string, aliasByID map[string]string) string {
	if policyrule.IsAnySubject(ids) {
		return "Any"
	}
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if a := aliasByID[id]; a != "" {
			parts = append(parts, a)
		} else {
			parts = append(parts, id)
		}
	}
	if len(parts) == 0 {
		return "Any"
	}
	return strings.Join(parts, ", ")
}

// buildEffectiveEgressRules assembles the unified, precedence-aware list of every effective egress rule across
// all surfaces. Authored rules and the built-in default are decisions (allow/deny/authenticate); known-bypass,
// Optimize, and cert-pin entries are inspection=bypass rows (raw-forward, still steered + policy-gated). The
// engine merges all of these at runtime — this view just makes them all visible and toggleable in one place.
func buildEffectiveEgressRules(in effectiveEgressInputs) effectiveEgressRuleListResponse {
	out := effectiveEgressRuleListResponse{
		Note: "Every effective egress rule, normalized to source → destination : service ⇒ access × inspection. Authored rules are editable; the built-in default and the known-bypass floor are toggleable; cert-pin bypass is managed in the approval queue. Bypass means the Edge raw-forwards without decrypting (still steered + policy-gated).",
	}

	// 1. Authored egress rules (editable, deletable).
	for i := range in.AuthoredRules {
		r := in.AuthoredRules[i]
		if r.Plane != policyrule.PlaneEgress {
			continue
		}
		svc := "HTTPS"
		if r.ServiceID != "" {
			if a := in.AliasByID[r.ServiceID]; a != "" {
				svc = a
			}
		}
		rule := r
		out.Rules = append(out.Rules, effectiveEgressRuleEntry{
			Kind: "authored", ID: r.ID, Name: r.Name, Priority: r.Priority,
			SourceText: subjectText(r.Source, in.AliasByID), DestText: subjectText(r.Destination, in.AliasByID),
			ServiceText: svc, Access: r.Action.Access, Inspection: r.Action.Inspection, Status: r.Status,
			Editable: true, Deletable: true, ToggleKind: "rule", Rule: &rule,
			DestinationUnresolved:   in.UnresolvedRuleIDs[r.ID],
			InspectionSourceWarning: in.InspectionSourceWarnings[r.ID],
		})
	}

	// 2. Built-in default policies (the catch-all etc.), toggleable via policy status, not editable here.
	for _, p := range in.Eval.OrderedPolicies() {
		createdBy := ""
		if p.CreatedBy != nil {
			createdBy = *p.CreatedBy
		}
		if policyProvenanceTag(decision.PolicyTraceEntry{PolicyID: p.ID, CreatedBy: createdBy}) != "built_in" {
			continue
		}
		// Service and inspection must come from the policy itself, not a fixed label: two built-in defaults
		// (the 443+decrypt catch-all and the any-port fallback below it) rendered as identical "Any → Any :
		// HTTPS · inspect" rows, and an operator reasonably concluded one was a duplicate — of a rule that was
		// the only thing keeping non-443 egress alive.
		svc := "Any"
		if fam, _ := p.Conditions["service_family"].(string); fam != "" {
			svc = strings.ToUpper(fam)
		} else if port, ok := p.Conditions["destination_port"].(float64); ok && port > 0 {
			svc = fmt.Sprintf("port %d", int(port))
		}
		inspection := "bypass"
		if p.InspectionProfileID != nil && strings.TrimSpace(*p.InspectionProfileID) != "" {
			inspection = "inspect"
		}
		out.Rules = append(out.Rules, effectiveEgressRuleEntry{
			Kind: "builtin_default", ID: p.ID, Name: p.Name, Priority: p.Priority,
			SourceText: "Any", DestText: "Any", ServiceText: svc,
			Access: p.Action.Decision, Inspection: inspection, Status: p.Status,
			Editable: false, Deletable: false, ToggleKind: "policy_status", PolicyID: p.ID,
			Detail: "Built-in default (config-sourced). Toggle here; detailed conditions are edited in the policy config.",
		})
	}

	// 3. Known-bypass floor — ONE aggregate entry, because the mechanism is a single all-or-nothing master toggle
	// (the OS/cert infrastructure that pins its certs: Apple push/iCloud, OS updates, OCSP, Windows update). One
	// card per group would falsely imply per-group control the model does not have; the entry lists the groups it
	// covers (DestText) so visibility is preserved while the toggle reads simply "Disable" / "Enable".
	if len(in.KnownGroups) > 0 {
		names := make([]string, 0, len(in.KnownGroups))
		allPatterns := []string{}
		anyActive := false
		for _, g := range in.KnownGroups {
			names = append(names, g.Name)
			allPatterns = append(allPatterns, g.Patterns...)
			if in.KnownEnabled && patternsAllPresent(g.Patterns, in.EffectiveBypass) {
				anyActive = true
			}
		}
		status := "off"
		if in.KnownEnabled && anyActive {
			status = "active"
		}
		out.Rules = append(out.Rules, effectiveEgressRuleEntry{
			Kind: "known_bypass", ID: "known-bypass", Priority: systemBypassFloorPriority,
			SourceText: "Any", DestText: strings.Join(names, ", "), ServiceText: "HTTPS",
			Access: "allow", Inspection: "bypass", Status: status,
			Editable: false, Deletable: false, ToggleKind: "known_bypass_master",
			Patterns: allPatterns,
			Detail:   "OS/cert infrastructure that pins its certificates — decrypting it breaks the OS. One all-or-nothing toggle.",
		})
	}

	// 4. SaaS Optimize bypass still selected via the legacy posture field (pre-B-1). Post-B-1 these are authored
	// rules and already appear above; this only surfaces a deployment that set posture.bypass_groups directly.
	for _, g := range in.OptimizeLegacy {
		out.Rules = append(out.Rules, effectiveEgressRuleEntry{
			Kind: "optimize_bypass", ID: "optimize-" + g.Name, Name: g.Name, Priority: systemBypassFloorPriority,
			SourceText: "Any", DestText: g.Name, ServiceText: "HTTPS",
			Access: "allow", Inspection: "bypass", Status: "active",
			Editable: false, Deletable: false, ToggleKind: "none",
			Patterns: g.Patterns, Detail: "Legacy posture bypass — toggle it as a rule in the SaaS Optimize section to make it a first-class Egress rule.",
		})
	}

	// 5. Cert-pin bypass — admin-approved (materialized) cert-pinned hosts, managed in the approval queue. A host
	// that now has an authored bypass rule (Phase C emits one on materialize) is skipped here — it is already
	// shown above as that authored rule, so the unified view lists it once.
	authoredBypass := map[string]bool{}
	for _, h := range in.AuthoredBypassHosts {
		authoredBypass[strings.TrimSpace(strings.ToLower(h))] = true
	}
	seen := map[string]bool{}
	for _, ref := range in.CertPinBypasses {
		h := strings.TrimSpace(strings.ToLower(ref.Host))
		if h == "" || seen[h] || authoredBypass[h] {
			continue
		}
		seen[h] = true
		out.Rules = append(out.Rules, effectiveEgressRuleEntry{
			Kind: "cert_pin_bypass", ID: "certpin-" + h, Name: h, Priority: systemBypassFloorPriority,
			SourceText: "Any", DestText: h, ServiceText: "HTTPS",
			Access: "allow", Inspection: "bypass", Status: "active",
			Editable: false, Deletable: false, ToggleKind: "cert_pin_revoke", CandidateID: ref.CandidateID,
			Detail: "Admin-approved cert-pin bypass. Revoke re-intercepts the host (suppresses the candidate).",
		})
	}

	// Stable order: by ascending priority, then kind, then id — authored low-priority rules first, the catch-all
	// default (priority 1000000) last, bypass floors grouped by their nominal priority in between.
	sort.SliceStable(out.Rules, func(i, j int) bool {
		a, b := out.Rules[i], out.Rules[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.ID < b.ID
	})
	return out
}
