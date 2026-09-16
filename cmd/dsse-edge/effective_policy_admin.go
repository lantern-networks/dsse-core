package main

import (
	"strings"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/interception"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/model"
)

// effectivePolicyEntry is one row of the Effective-Policy ("Why") view: a precedence-ordered policy-trace entry
// from the decision engine plus this edge's provenance tag for it. The engine (dsse-core) is provenance-
// agnostic — it only knows policy IDs — so the edge, which loaded the policies, tags each one's source. This is
// the visibility that was missing on 2026-06-23, when an authored Authenticate rule silently lost a priority
// tie to a built-in allow the operator could not see.
type effectivePolicyEntry struct {
	decision.PolicyTraceEntry
	Source string `json:"source"` // "authored" | "built_in"
}

// inspectionBasis is the inspect/bypass layer of the effective-config view for a destination: whether the Edge
// decrypts (inspects) the flow or raw-forwards (bypasses) it, and WHICH source decided that. A bypassed flow is
// still steered and policy-gated — the Edge merely declines to terminate its TLS — so this is orthogonal to the
// policy decision (allow/deny/authenticate) above. Attribution follows the current posture, known-bypass
// catalog, authored rules and configured host sets. Candidate history does not authorize inspection bypass.
type inspectionBasis struct {
	Decision string `json:"decision"`         // "inspect" | "bypass" | "depends_on_device"
	Source   string `json:"source"`           // default_decrypt_all | decrypt_allowlist | known_bypass | authored_bypass | static_bypass | bypass_default
	Detail   string `json:"detail,omitempty"` // e.g. the known-bypass group name
}

// inspectionSources are the live engine pattern sets, gathered by the edge (which owns them). They mirror the
// engine's shared and device-specific patterns. A host-only preview cannot choose a source device.
// The per-bypass-source fields are only for attribution — labelling WHICH source put a host in the bypass set.
type inspectionSources struct {
	InterceptHosts  []string            // the engine's live intercept set ("*" = decrypt-all; narrower = decrypt allowlist)
	EffectiveBypass []string            // the engine's live raw-forward set — always wins over intercept
	KnownGroups     []knownbypass.Group // curated named bypass groups, for attribution
	AuthoredBypass  []string            // authored egress rules whose inspection axis is bypass, for attribution
	DeviceIntercept map[string][]string
	DeviceBypass    map[string][]string
}

// effectivePolicyResponse is the precedence-ordered, provenance-tagged decision basis for a destination, plus
// the inspect/bypass basis — the two layers that together decide a steered HTTPS flow.
type effectivePolicyResponse struct {
	Destination    string `json:"destination"`
	ActorType      string `json:"actor_type"`
	WinnerPolicyID string `json:"winner_policy_id"`
	WinnerDecision string `json:"winner_decision"`
	FinalDecision  string `json:"final_decision"`
	FinalPolicyID  string `json:"final_policy_id"`
	// ServiceFamily is what this answer was computed for, and ServiceFamilySource says where it came from —
	// asked for, derived from the port, or neither. A preview that silently assumes one answers a question the
	// operator did not ask, and they compare it against an Edge that answered theirs.
	ServiceFamily       string                 `json:"service_family"`
	ServiceFamilySource string                 `json:"service_family_source"`
	DestinationPort     int                    `json:"destination_port"`
	Inspection          inspectionBasis        `json:"inspection"`
	Trace               []effectivePolicyEntry `json:"trace"`
	Note                string                 `json:"note"`
}

// effectivePolicyListEntry is one row of the standing "all policies" listing — every policy in the engine,
// authored or built-in, source-tagged, in precedence order. Surfaces the full policy set rather than leaving
// built-in policies discoverable only per-destination.
type effectivePolicyListEntry struct {
	PolicyID string `json:"policy_id"`
	Name     string `json:"name,omitempty"`
	Priority int    `json:"priority"`
	Decision string `json:"decision"`
	Status   string `json:"status"`
	Source   string `json:"source"` // authored | built_in
}

type effectivePolicyListResponse struct {
	Policies []effectivePolicyListEntry `json:"policies"`
	Note     string                     `json:"note"`
}

// effectivePolicyList returns the full precedence-ordered policy set with provenance tags. Read-only.
func effectivePolicyList(eval decision.Evaluator) effectivePolicyListResponse {
	ordered := eval.OrderedPolicies()
	resp := effectivePolicyListResponse{
		Policies: make([]effectivePolicyListEntry, 0, len(ordered)),
		Note:     "Every policy the engine evaluates, in precedence order (first match wins), each tagged by source. authored = compiled from an Egress/East-West rule or directly upserted; built_in = loaded via -policy / the bundle (its source of truth is the config, edited there).",
	}
	for _, p := range ordered {
		createdBy := ""
		if p.CreatedBy != nil {
			createdBy = *p.CreatedBy
		}
		resp.Policies = append(resp.Policies, effectivePolicyListEntry{
			PolicyID: p.ID,
			Name:     p.Name,
			Priority: p.Priority,
			Decision: p.Action.Decision,
			Status:   p.Status,
			Source:   policyProvenanceTag(decision.PolicyTraceEntry{PolicyID: p.ID, CreatedBy: createdBy}),
		})
	}
	return resp
}

// effectivePolicyQuery holds the parsed request shape an operator wants explained.
type effectivePolicyQuery struct {
	Destination       string
	ActorType         string
	ServiceFamily     string
	DestinationPort   int
	SaaSApplicationID string
}

// policyProvenanceTag classifies a policy by where it came from so the Effective-Policy view can show built-in
// competitors distinctly from authored intent. Compiled egress rules carry the "rule-egress-" ID owned by the
// rule compiler; a directly-upserted policy carries operator attribution (created_by); everything else is a
// built-in loaded via -policy or the bundle — which is NOT shown in the rule editor and is exactly the kind of
// hidden competitor that out-precedenced an authored rule on 2026-06-23.
func policyProvenanceTag(entry decision.PolicyTraceEntry) string {
	if strings.HasPrefix(entry.PolicyID, "rule-egress-") || strings.HasPrefix(entry.PolicyID, "rule-eastwest-") {
		return "authored"
	}
	if strings.TrimSpace(entry.CreatedBy) != "" {
		return "authored"
	}
	return "built_in"
}

// classifyInspection reports whether host is inspected (decrypted) or bypassed (raw-forwarded) and which source
// decided it, mirroring the engine's own Matches: the bypass set ALWAYS wins (raw-forward), and otherwise a
// host is decrypted IFF it is in the intercept set. So under decrypt-all (intercept "*") everything not bypassed
// is decrypted; under bypass-default (a decrypt allowlist) only allowlisted hosts are decrypted and everything
// else is bypassed by default. Bypass attribution is best-effort.
func classifyInspection(host string, src inspectionSources) inspectionBasis {
	// 1. Bypass set wins — attribute the source.
	if interception.HostMatchesPatterns(host, src.EffectiveBypass) {
		for _, g := range src.KnownGroups {
			if interception.HostMatchesPatterns(host, g.Patterns) {
				return inspectionBasis{Decision: "bypass", Source: "known_bypass", Detail: g.Name}
			}
		}
		if interception.HostMatchesPatterns(host, src.AuthoredBypass) {
			return inspectionBasis{Decision: "bypass", Source: "authored_bypass"}
		}
		return inspectionBasis{Decision: "bypass", Source: "static_bypass"}
	}
	deviceHost := func(patterns map[string][]string) bool {
		for _, hosts := range patterns {
			if interception.HostMatchesPatterns(host, hosts) {
				return true
			}
		}
		return false
	}
	// A destination-only preview has no authenticated source device. Do not
	// present one device's exception as the answer for every connection.
	baseInspect := interception.HostMatchesPatterns(host, src.InterceptHosts)
	if (baseInspect && deviceHost(src.DeviceBypass)) || (!baseInspect && deviceHost(src.DeviceIntercept)) {
		return inspectionBasis{Decision: "depends_on_device", Source: "device_rule"}
	}
	// 2. Not bypassed: decrypted IFF in the intercept set.
	if interception.HostMatchesPatterns(host, src.InterceptHosts) {
		source := "decrypt_allowlist"
		for _, h := range src.InterceptHosts {
			if strings.TrimSpace(h) == "*" {
				source = "default_decrypt_all"
				break
			}
		}
		return inspectionBasis{Decision: "inspect", Source: source}
	}
	// 3. bypass-default: not in the decrypt allowlist -> bypassed by default.
	return inspectionBasis{Decision: "bypass", Source: "bypass_default"}
}

// effectivePolicyForDestination builds the precedence-ordered, provenance-tagged policy basis for a destination
// AND its inspect/bypass basis — the complete effective-configuration view for that host. Read-only.
func effectivePolicyForDestination(eval decision.Evaluator, tenantID string, q effectivePolicyQuery, bypass inspectionSources) effectivePolicyResponse {
	// ★★★ THE PORT DECIDES THE SERVICE FAMILY, HERE AS ON THE DATAPATH (2026-08-25, measured while asking why a
	// flow to port 8080 was denied). This preview took a destination_port and did NOT derive the family from
	// it — it defaulted to "https" — so an operator asking about port 8080 was answered about HTTPS. On a
	// deployment whose only allow rule is the starting "Allow HTTPS", that inverts the answer: the screen an
	// operator opens BECAUSE traffic is being denied said allow, and the Edge denied it, for the same flow.
	//
	// steerServiceFamilyForPort is the datapath's own map, used unchanged. Two places deciding the same thing
	// by different rules is how a preview stops previewing anything.
	family := strings.TrimSpace(q.ServiceFamily)
	familySource := "asked"
	if family == "" {
		family, familySource = steerServiceFamilyForPort(q.DestinationPort), "derived from the port"
		if family == "" {
			// The port names no family this deployment knows. The datapath evaluates with an empty family
			// then, so this does too — and says so, because "no family" and "https" are different questions
			// and only one of them was asked.
			familySource = "none — this port names no service family, so family-scoped rules cannot match"
		}
	}
	req := model.DecisionRequest{
		TenantID:          tenantID,
		ActorType:         valueOrDefault(q.ActorType, "human"),
		ServiceFamily:     family,
		DestinationPort:   q.DestinationPort,
		Protocol:          "tcp",
		SNI:               q.Destination,
		FQDN:              q.Destination,
		SaaSApplicationID: q.SaaSApplicationID,
	}
	exp := eval.ExplainDecision(req)
	resp := effectivePolicyResponse{
		Destination:    q.Destination,
		ActorType:      exp.ActorType,
		WinnerPolicyID: exp.WinnerPolicyID,
		WinnerDecision: exp.WinnerDecision,
		FinalDecision:  exp.FinalDecision,
		FinalPolicyID:  exp.FinalPolicyID,
		ServiceFamily:  family,
		// Which question was actually answered. An operator comparing this against what the Edge did needs to
		// see the assumption, not infer it from a decision that disagrees with them.
		ServiceFamilySource: familySource,
		DestinationPort:     q.DestinationPort,
		Inspection:          classifyInspection(q.Destination, bypass),
		Trace:               make([]effectivePolicyEntry, 0, len(exp.Trace)),
		Note:                "Two layers: 'trace'/'final_decision' is the policy basis (allow/deny/authenticate); 'inspection' is whether the Edge decrypts or bypasses TLS. A bypassed flow is still steered and policy-gated.",
	}
	for _, tr := range exp.Trace {
		resp.Trace = append(resp.Trace, effectivePolicyEntry{PolicyTraceEntry: tr, Source: policyProvenanceTag(tr)})
	}
	return resp
}
