// Package policyrule is the unified rule-authoring model an operator edits in the Console: a rule reads
// `source → destination : service ⇒ action`, in a plane (east-west or egress) and — for east-west — a
// direction (outbound or inbound). Source/destination reference the asset catalog (endpoints or groups) by
// id; service references a catalog service (egress defaults to HTTPS). The action is two orthogonal axes:
// access (allow/authenticate/deny) × inspection (inspect/bypass), composable.
//
// This model lives in dsse-core (not the proprietary Console) so audit logs and decisions reference the
// named, authored rule — the same reason the asset catalog (subjects) lives here. Mapping an authored rule
// DOWN to the live enforcement primitives (east-west rules, egress policies, TLS-bypass set) is a separate
// concern handled by the edge; this package is the representation + storage the editor reads and writes.
package policyrule

import (
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

// Planes — east-west (internal/lateral) is the centerpiece; egress (north-south to the internet) is the
// other surface. They are edited in separate views but share this model and vocabulary.
const (
	PlaneEastWest = "east_west"
	PlaneEgress   = "egress"
)

// Directions apply to east-west only. Outbound (client→server) enforces on both macOS NE and Windows WFP;
// inbound (server→client, server-initiated) enforces on Windows WFP only — macOS NETransparentProxy is
// outbound-only, so an inbound rule whose receivers are macOS cannot be enforced (validated at the edge).
const (
	DirectionOutbound = "outbound"
	DirectionInbound  = "inbound"
)

// Access axis — what happens to the connection on the identity/authorization dimension.
const (
	AccessAllow        = "allow"        // permit
	AccessAuthenticate = "authenticate" // hold for an OOB step-up, then a short-lived grant (east-west today)
	AccessDeny         = "deny"         // block
)

// Inspection axis — whether the (TLS) payload is decrypted or forwarded raw. Orthogonal to access: an
// allowed flow may be inspected or bypassed; an authenticated flow may likewise be inspected or bypassed.
const (
	InspectionInspect = "inspect" // decrypt (the default — the ZTNA norm is decrypt-all)
	InspectionBypass  = "bypass"  // raw-forward without decryption
)

// Rule lifecycle status.
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// Stage is the East-West policy-learning lifecycle position of a rule (Observe → Warn → Enforce), ORTHOGONAL to
// the action (allow/authenticate/deny). It is the safe-adoption ramp: a rule can be authored (and its access set)
// while it only WARNS, then flipped to Enforce once the operator trusts it. See
// docs/east_west_policy_learning_lifecycle_gap.md. Default (empty) = Enforce (the action bites immediately).
//   - StageEnforce: the action applies as written (authenticate holds, deny blocks) — the normal rule.
//   - StageWarn: a dry-run — an authenticate/deny rule is SOFTENED to allow-the-flow while flagging a non-holding
//     "this connection is monitored; authentication will soon be required" notice. Lets the operator watch what a
//     rule WOULD affect before it bites. (No effect on an allow rule — nothing to soften.)
const (
	StageEnforce = "enforce"
	StageWarn    = "warn"
)

// SubjectAny is the reserved source/destination token meaning "any" (an explicit wildcard). It is NOT an
// asset id; the compilers translate it to a wildcard match. A selector is never wildcard by being empty —
// empty is rejected — so "any" is always an explicit operator choice.
const SubjectAny = "*"

// IsAnySubject reports whether a source/destination selector is the explicit "any" wildcard.
func IsAnySubject(ids []string) bool {
	for _, id := range ids {
		if strings.TrimSpace(id) == SubjectAny {
			return true
		}
	}
	return false
}

// IdentityGroupPrefix marks a source selector as an IDENTITY group (an IdP user-group) rather than a device /
// asset id. A rule whose "Who" is `idgroup:<name>` authorizes that IdP group — which applies to the user from
// ANY device, INCLUDING the agentless browser (clientless). The egress compiler translates it to a user_groups
// condition (matched against the authenticated session's groups), never a device restriction. This is the single
// model addition that lets one egress rule express published-app (clientless) access — see
// docs/published_app_access_egress_unification_design.md.
const IdentityGroupPrefix = "idgroup:"

// IdentityGroupToken reports whether a source selector names an IdP identity group and, if so, returns the group
// name (the value matched against the request's user_groups).
func IdentityGroupToken(id string) (string, bool) {
	s := strings.TrimSpace(id)
	if !strings.HasPrefix(s, IdentityGroupPrefix) {
		return "", false
	}
	g := strings.TrimSpace(strings.TrimPrefix(s, IdentityGroupPrefix))
	if g == "" {
		return "", false
	}
	return g, true
}

// IdentityUserPrefix marks a source selector as an INDIVIDUAL IdP user (a specific person) rather than a group,
// device, or agent. A rule whose "Who" is `iduser:<id>` authorizes that ONE user from ANY device (browser
// included). The egress compiler translates it to a user_id condition (matched against the request's user_id).
// This is the per-person parallel of idgroup: — the rule editor's group drill-down lets an operator pick either a
// whole IdP group (idgroup:) or an individual member (iduser:).
const IdentityUserPrefix = "iduser:"

// IdentityUserToken reports whether a source selector names an individual IdP user and, if so, returns the user
// id (the value matched against the request's user_id).
func IdentityUserToken(id string) (string, bool) {
	s := strings.TrimSpace(id)
	if !strings.HasPrefix(s, IdentityUserPrefix) {
		return "", false
	}
	u := strings.TrimSpace(strings.TrimPrefix(s, IdentityUserPrefix))
	if u == "" {
		return "", false
	}
	return u, true
}

// AgentPrefix marks a source selector as a NON-HUMAN IDENTITY (an AI agent / service account) rather than a
// device or an IdP user-group. A rule whose "Who" is `nhi:<id>` governs that automated actor: the egress
// compiler translates it to an actor_nhi_id condition (matched against the decision request's ActorNHIID), and
// the rule's AllowedToolIDs become the policy's agentic tool boundary. This is the agent parallel of
// idgroup: — one authoring model for humans (idgroup) and agents (nhi) in the same access-rule editor. See
// docs/agentic_governance_configuration_design.md (S4).
const AgentPrefix = "nhi:"

// AgentToken reports whether a source selector names an agent/NHI and, if so, returns the NHI id (the value
// matched against the request's actor_nhi_id).
func AgentToken(id string) (string, bool) {
	s := strings.TrimSpace(id)
	if !strings.HasPrefix(s, AgentPrefix) {
		return "", false
	}
	a := strings.TrimSpace(strings.TrimPrefix(s, AgentPrefix))
	if a == "" {
		return "", false
	}
	return a, true
}

// Action is the two-axis action plus modifiers that apply on top of access.
type Action struct {
	Access     string `json:"access"`     // AccessAllow | AccessAuthenticate | AccessDeny
	Inspection string `json:"inspection"` // InspectionInspect | InspectionBypass (default inspect)
	// RequireWorkloadAttestation gates a machine/non-interactive actor on verified workload identity. It is
	// machine-side and needs no operator notification (unlike human approval, which is omitted until a
	// delivery channel exists).
	RequireWorkloadAttestation bool `json:"require_workload_attestation,omitempty"`
	// GrantTTLSeconds caps the short-lived grant minted when access is authenticate (0 = use the tenant cap).
	GrantTTLSeconds int `json:"grant_ttl_seconds,omitempty"`
	// Step-up assurance for access=authenticate (the controls that make an east-west hop bite against a stolen
	// user credential — see docs/lateral_movement_per_hop_authentication.md). RequiredIdPID names a registered
	// IdP; RequiredAMR lists methods the step-up token must include (e.g. "phishing_resistant"); MinACR is an
	// assurance floor; MaxAgeSeconds forces a recent (not cached) auth.
	RequiredIdPID string   `json:"required_idp_id,omitempty"`
	MinACR        string   `json:"min_acr,omitempty"`
	RequiredAMR   []string `json:"required_amr,omitempty"`
	MaxAgeSeconds int      `json:"max_age_seconds,omitempty"`
	// DeviceAttestedAuto (default false) opts an authenticate-mode East-West rule into the machine/non-interactive
	// path: a flow with a VERIFIED mTLS device identity + trusted posture but NO human at the keyboard is released
	// by DEVICE attestation instead of holding forever for an impossible OOB ceremony. This is the "sensitivity
	// decides the mechanism" knob — set true on LOW-sensitivity destinations where device-attested lateral is
	// acceptable; leave false (+ a phishing-resistant MinACR) on crown-jewel destinations so a machine flow with no
	// human fails closed. Only meaningful when Access == authenticate.
	DeviceAttestedAuto bool `json:"device_attested_auto,omitempty"`
	// DLP is the third action axis (Access × Inspection × DLP): on an EGRESS rule whose traffic is inspected,
	// the compiled policy carries it (Policy.DLP) so the Edge scans the decrypted body/files for the listed
	// identifiers and applies OnMatch. Meaningful only with Inspection=inspect. nil = no DLP on this rule.
	DLP *model.DLPSpec `json:"dlp,omitempty"`
}

// Rule is one authored rule. Source/Destination are asset-catalog ids (endpoints or groups); ServiceID is
// an asset-catalog service id (optional for egress, which is HTTPS by default).
type Rule struct {
	ID          string   `json:"id"`
	TenantID    string   `json:"tenant_id"`
	Plane       string   `json:"plane"`               // PlaneEastWest | PlaneEgress
	Direction   string   `json:"direction,omitempty"` // east-west only: DirectionOutbound | DirectionInbound
	Priority    int      `json:"priority"`
	Name        string   `json:"name,omitempty"`
	Source      []string `json:"source"`               // asset-catalog endpoint/group ids
	Destination []string `json:"destination"`          // asset-catalog endpoint/group ids
	ServiceID   string   `json:"service_id,omitempty"` // asset-catalog service id (egress: optional)
	Action      Action   `json:"action"`
	// AllowedToolIDs is the agentic tool boundary for an agent rule (Who = nhi:<id>): the tools the
	// agent may call. It compiles to the policy's AllowedToolIDs — a tool outside it is denied before execution.
	// Empty ⇒ no tool boundary. Ignored for human/device rules (they carry no ActorNHIID).
	AllowedToolIDs []string `json:"allowed_tool_ids,omitempty"`
	// RiskAtLeast gates the rule on the subject's CURRENT risk: the compiled policy only matches when the decision
	// request's risk_state_severity is at least this level (a high-risk marking on the device or the user). Empty
	// or "none" = no risk gate. Paired with Action.Access=authenticate it expresses "high-risk → re-authenticate".
	RiskAtLeast string `json:"risk_at_least,omitempty"` // "" | low | medium | high | critical
	Status      string `json:"status"`                  // StatusActive | StatusDisabled
	// Stage is the East-West learning-lifecycle position (StageEnforce default | StageWarn). Warn softens an
	// authenticate/deny rule to allow-with-notice (non-holding). East-west only; ignored on egress rules.
	Stage string `json:"stage,omitempty"`
}

// riskSeverityRank orders risk severities so a rule's RiskAtLeast threshold expands to "this level or higher".
var riskSeverityRank = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// RiskSeveritiesAtLeast returns the severities >= threshold (for a risk_state_severity "in" condition). An empty,
// "none", or unrecognized threshold returns nil (no gate).
func RiskSeveritiesAtLeast(threshold string) []string {
	minRank, ok := riskSeverityRank[strings.ToLower(strings.TrimSpace(threshold))]
	if !ok {
		return nil
	}
	var out []string
	for _, s := range []string{"low", "medium", "high", "critical"} {
		if riskSeverityRank[s] >= minRank {
			out = append(out, s)
		}
	}
	return out
}

// normalizeAndValidate fills defaults and enforces the model's invariants. It does NOT resolve asset ids or
// receiver platforms (the edge does that — e.g. the macOS-inbound check); it validates the rule in isolation.
func (r *Rule) normalizeAndValidate() error {
	r.TenantID = strings.TrimSpace(r.TenantID)
	if r.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	r.Plane = strings.ToLower(strings.TrimSpace(r.Plane))
	switch r.Plane {
	case PlaneEastWest:
		r.Direction = strings.ToLower(strings.TrimSpace(r.Direction))
		if r.Direction == "" {
			r.Direction = DirectionOutbound
		}
		if r.Direction != DirectionOutbound && r.Direction != DirectionInbound {
			return fmt.Errorf("east-west direction %q is invalid (want outbound|inbound)", r.Direction)
		}
	case PlaneEgress:
		if strings.TrimSpace(r.Direction) != "" {
			return fmt.Errorf("egress rules have no direction")
		}
	default:
		return fmt.Errorf("plane %q is invalid (want east_west|egress)", r.Plane)
	}

	r.Action.Access = strings.ToLower(strings.TrimSpace(r.Action.Access))
	switch r.Action.Access {
	case AccessAllow, AccessAuthenticate, AccessDeny:
	default:
		return fmt.Errorf("access %q is invalid (want allow|authenticate|deny)", r.Action.Access)
	}
	r.Action.Inspection = strings.ToLower(strings.TrimSpace(r.Action.Inspection))
	if r.Action.Inspection == "" {
		r.Action.Inspection = InspectionInspect
	}
	if r.Action.Inspection != InspectionInspect && r.Action.Inspection != InspectionBypass {
		return fmt.Errorf("inspection %q is invalid (want inspect|bypass)", r.Action.Inspection)
	}
	// A deny that also bypasses inspection is contradictory (nothing to forward) — reject it early.
	if r.Action.Access == AccessDeny && r.Action.Inspection == InspectionBypass {
		return fmt.Errorf("deny cannot bypass inspection")
	}
	if r.Action.GrantTTLSeconds < 0 {
		return fmt.Errorf("grant_ttl_seconds cannot be negative")
	}

	if len(r.Source) == 0 {
		return fmt.Errorf("source requires at least one endpoint or group (or Any)")
	}
	if len(r.Destination) == 0 {
		return fmt.Errorf("destination requires at least one endpoint or group (or Any)")
	}
	for _, id := range r.Source {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("source contains a blank id")
		}
	}
	for _, id := range r.Destination {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("destination contains a blank id")
		}
	}
	// Canonicalize an explicit wildcard so downstream sees exactly ["*"].
	if IsAnySubject(r.Source) {
		r.Source = []string{SubjectAny}
	}
	if IsAnySubject(r.Destination) {
		r.Destination = []string{SubjectAny}
	}
	r.RiskAtLeast = strings.ToLower(strings.TrimSpace(r.RiskAtLeast))
	if r.RiskAtLeast == "none" {
		r.RiskAtLeast = ""
	}
	if r.RiskAtLeast != "" {
		if _, ok := riskSeverityRank[r.RiskAtLeast]; !ok {
			return fmt.Errorf("risk_at_least %q is invalid (want low|medium|high|critical)", r.RiskAtLeast)
		}
	}
	r.Status = strings.ToLower(strings.TrimSpace(r.Status))
	if r.Status == "" {
		r.Status = StatusActive
	}
	if r.Status != StatusActive && r.Status != StatusDisabled {
		return fmt.Errorf("status %q is invalid (want active|disabled)", r.Status)
	}
	r.Stage = strings.ToLower(strings.TrimSpace(r.Stage))
	if r.Stage == "" {
		r.Stage = StageEnforce
	}
	if r.Stage != StageEnforce && r.Stage != StageWarn {
		return fmt.Errorf("stage %q is invalid (want enforce|warn)", r.Stage)
	}
	// Warn is an EAST-WEST-only ramp construct (the lifecycle is east-west only). An egress rule may only enforce.
	if r.Stage == StageWarn && r.Plane != PlaneEastWest {
		return fmt.Errorf("stage warn is only valid on east-west rules")
	}
	return nil
}
