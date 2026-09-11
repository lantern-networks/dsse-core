package decision

import (
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// east_west: per-hop authorization for east-west (internal/lateral) traffic. This is the prevention
// answer to careful low-and-slow lateral movement that traffic-pattern detection cannot catch: instead
// of "allow east-west and watch for anomalies", east-west is DEFAULT-DENY and each (identity x
// destination x protocol) hop must be explicitly authorized. E1 = policy model + decision-path mode resolution.
//
// Gated by Evaluator.EastWestEnabled: when false (the default) this layer is inert and every decision is
// byte-identical to legacy behaviour. When true, east-west-protocol requests are governed solely by
// east-west rules with default-deny.

// East-west authorization modes (admin sets one per (source x destination x protocol)).
const (
	EastWestModeAllow        = "allow"        // permitted transparently (no step-up)
	EastWestModeAuthenticate = "authenticate" // hold + interactive auth ceremony, then ephemeral grant (E3/E4)
	EastWestModeDeny         = "deny"         // blocked
)

// eastWestProtocols are the internal/lateral service families subject to east-west per-hop authorization.
var eastWestProtocols = map[string]bool{
	"rdp": true, "smb": true, "cifs": true, "winrm": true, "wmi_rpc": true,
	"dcom_rpc": true, "ssh": true, "vnc": true, "rmm": true, "rmm_agent": true,
	"database": true, "db": true, "management_tcp": true,
}

// IsEastWestProtocol reports whether a service family is an east-west (internal/lateral) protocol.
func IsEastWestProtocol(serviceFamily string) bool {
	return eastWestProtocols[strings.ToLower(strings.TrimSpace(serviceFamily))]
}

// EastWestRule authorizes east-west access from a source selector to a destination over a protocol set,
// with a mode. Empty selector lists mean "any". Highest Priority wins.
type EastWestRule struct {
	ID           string
	Priority     int
	SourceUsers  []string // matches req.UserID / req.SubjectUserID
	SourceGroups []string // matches any of req.UserGroups
	// SourceDevices restricts the source to specific device identities, matched against req.DeviceID. This is
	// the device-centric source selector authored rules compile to (a steered device or a group of them), so
	// east-west micro-segmentation can say WHICH devices may reach a destination — not just which users.
	SourceDevices []string
	Destinations  []string // matches req.Destination / req.ApplicationID / req.FQDN
	Protocols     []string // matches req.ServiceFamily (east-west protocols)
	Mode          string   // allow | authenticate | deny
	// Warn (learning-lifecycle Warn stage) softens this rule to a NON-HOLDING dry-run: an authenticate/deny rule
	// allows the flow through but flags a "monitored; authentication will soon be required" notice, so the
	// operator can watch what the rule WOULD affect before it bites. No effect on an allow rule. See
	// docs/east_west_policy_learning_lifecycle_gap.md.
	Warn bool
	// MaxTTLSeconds caps the lifetime of grants issued for this rule (E6 sensitivity tiering). 0 = no
	// per-rule cap (the tenant max / issuance default applies). Set a short value on sensitive
	// destinations (domain controllers, file servers, admin planes).
	MaxTTLSeconds int
	// DeviceAttestedAuto (opt-in; default false) lets an authenticate-mode flow that CANNOT do an interactive
	// OOB ceremony — a non-interactive / machine-account / WFP-steered lateral flow with no user — be allowed
	// by DEVICE attestation instead: a verified mTLS device identity + a trusted posture tier. This is the
	// machine-flow answer to the AD release gate. Default off keeps machine flows fail-closed (hold) unless a
	// rule explicitly opts in for a destination/protocol where device-attested lateral is acceptable.
	DeviceAttestedAuto bool
	// Step-up assurance the authenticate ceremony must satisfy (carried from the authored rule). RequiredIdPID
	// names the IdP the step-up must use; RequiredAMR are methods the token must include (e.g.
	// "phishing_resistant"); MinACR is an assurance floor; MaxAgeSeconds forces a recent auth. These make an
	// east-west hop bite against a stolen user credential — see
	// docs/lateral_movement_per_hop_authentication.md. Empty = no assurance floor (weaker; prefer setting
	// phishing-resistant + a short max-age on lateral hops).
	RequiredIdPID string
	MinACR        string
	RequiredAMR   []string
	MaxAgeSeconds int
	// RiskSeverities gates the rule on the subject's CURRENT risk, matched against req.RiskStateSeverity.
	// It is the authored rule's RiskAtLeast threshold ALREADY EXPANDED to "that level or higher" by the
	// compiler (policyrule.RiskSeveritiesAtLeast) — the expansion lives there because policyrule imports
	// decision, not the other way round. Empty = no risk gate (wildcard), which is also what an empty/"none"
	// RiskAtLeast compiles to.
	//
	// Without this the east-west plane had NO risk gate at all while the Console rendered and POSTed
	// risk_at_least for BOTH planes: an authored "east-west / ssh / risk>=high / deny" saved successfully and
	// silently became an ALL-risk-levels deny.
	RiskSeverities []string
}

// AuthoritativeDeviceIdentity returns the device identity east-west matching must use: the transport-bound
// identity (verified mTLS CN, set by the Edge — the client cannot choose it) when present, else the
// client-claimed DeviceID. The claimed DeviceID is NEVER consulted when a transport identity exists:
// accepting it as an alternate match let any device claim another's DeviceID to borrow its grant or to
// satisfy a source-device rule selector, defeating the per-hop device binding. The claimed-ID fallback
// remains only for requests that carry no transport identity at all (non-steered paths and the synthetic
// grant-binding request EffectiveTTL builds).
func AuthoritativeDeviceIdentity(req model.DecisionRequest) string {
	if id := strings.TrimSpace(req.TransportDeviceIdentity); id != "" {
		return id
	}
	return strings.TrimSpace(req.DeviceID)
}

func eastWestSelectorMatches(selector []string, candidates ...string) bool {
	if len(selector) == 0 {
		return true // empty selector = wildcard
	}
	for _, s := range selector {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		for _, c := range candidates {
			if s == strings.TrimSpace(c) {
				return true
			}
		}
	}
	return false
}

func (r EastWestRule) matches(req model.DecisionRequest) bool {
	// Source is a union of the selectors that are SET: users (UserID/SubjectUserID), groups (UserGroups), and
	// devices (the AUTHORITATIVE device identity — transport-bound when present, so a flow cannot claim
	// another device's ID to satisfy a source-device selector). When none is set, source is wildcard. When any
	// is set, at least one set selector must match — an unset selector never makes the source wildcard (so a
	// device-only rule really restricts to those devices).
	if len(r.SourceUsers) > 0 || len(r.SourceGroups) > 0 || len(r.SourceDevices) > 0 {
		sourceMatch := (len(r.SourceUsers) > 0 && eastWestSelectorMatches(r.SourceUsers, req.UserID, req.SubjectUserID)) ||
			(len(r.SourceGroups) > 0 && eastWestSelectorMatches(r.SourceGroups, req.UserGroups...)) ||
			(len(r.SourceDevices) > 0 && eastWestSelectorMatches(r.SourceDevices, AuthoritativeDeviceIdentity(req)))
		if !sourceMatch {
			return false
		}
	}
	if !eastWestSelectorMatches(r.Destinations, req.Destination, req.ApplicationID, req.FQDN) {
		return false
	}
	if !eastWestSelectorMatches(r.Protocols, req.ServiceFamily) {
		return false
	}
	// Risk gate: an empty set is wildcard (no gate), so an ungated rule behaves exactly as before. A gated rule
	// bites ONLY at or above its authored threshold — a rule that does not match here falls through to the next
	// rule and ultimately to the plane's default-deny posture.
	if !eastWestSelectorMatches(r.RiskSeverities, req.RiskStateSeverity) {
		return false
	}
	return true
}

// MatchedEastWestRule returns the winning east-west rule matching a request (used at grant issuance to read the
// rule's sensitivity-tier MaxTTLSeconds, E6). Precedence is LOWER-priority-number-wins — the SAME contract as the
// egress/general policy plane (evaluator.go / policy.Store sort `Priority <`) and the Console "Priority (lower
// wins)" label; east-west previously sorted the other way (higher-wins), silently inverting precedence for
// operators who authored rules through the GUI. Ties break by insertion order (stable).
func MatchedEastWestRule(rules []EastWestRule, req model.DecisionRequest) (EastWestRule, bool) {
	ordered := make([]EastWestRule, len(rules))
	copy(ordered, rules)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Priority < ordered[j].Priority })
	for _, r := range ordered {
		if r.matches(req) {
			return r, true
		}
	}
	return EastWestRule{}, false
}

// EastWestGrant is an active ephemeral grant that releases an authenticate-mode hold for a matching
// (identity x device x destination x protocol) until ExpiresAt. Empty binding fields mean "any".
type EastWestGrant struct {
	SubjectUserID string
	DeviceID      string
	Destination   string
	Protocol      string
	ExpiresAt     time.Time
	// LastUsedAt + IdleTTLSeconds implement idle expiry (E6): a grant unused for longer than the idle
	// window stops releasing, even before ExpiresAt. IdleTTLSeconds 0 = no idle limit.
	LastUsedAt     time.Time
	IdleTTLSeconds int
}

func (g EastWestGrant) matches(req model.DecisionRequest, now time.Time) bool {
	if !now.Before(g.ExpiresAt) {
		return false // expired (absolute TTL)
	}
	if g.IdleTTLSeconds > 0 && now.Sub(g.LastUsedAt) > time.Duration(g.IdleTTLSeconds)*time.Second {
		return false // idle-expired
	}
	if g.Protocol != "" && !strings.EqualFold(g.Protocol, strings.TrimSpace(req.ServiceFamily)) {
		return false
	}
	if g.SubjectUserID != "" && g.SubjectUserID != req.SubjectUserID && g.SubjectUserID != req.UserID {
		return false
	}
	// Device binding. Match the grant's device against the AUTHORITATIVE device identity ONLY: the transport
	// identity (verified mTLS, set on steered flows by enrichDecisionRequestWithTransportIdentity) when
	// present, else the client claim. The claimed DeviceID must not be an ALTERNATE match path alongside the
	// transport identity — that let a flow whose transport identity is win-dev-2 claim DeviceID=win-dev-1 in
	// its request body and borrow win-dev-1's grant, defeating the per-hop device binding this comment
	// promises. A DEVICE-ATTESTED grant (issued for a steered flow's transport identity) still releases that
	// flow even though the WFP request carries no client DeviceID.
	if g.DeviceID != "" && g.DeviceID != AuthoritativeDeviceIdentity(req) {
		return false
	}
	if g.Destination != "" && g.Destination != req.Destination && g.Destination != req.ApplicationID {
		return false
	}
	return true
}

func (e Evaluator) hasValidEastWestGrant(req model.DecisionRequest, now time.Time) bool {
	for _, g := range e.EastWestGrants {
		if g.matches(req, now) {
			return true
		}
	}
	return false
}

// eastWestDeviceAttestationEligible reports whether a flow may be authorized by DEVICE attestation instead of
// an interactive OOB ceremony (which a machine/non-interactive flow cannot perform): it must present a VERIFIED,
// enrolled mTLS device identity — that verified device identity IS the machine authentication in lieu of a human.
//
// We deliberately do NOT also gate on a posture trust tier. The steer-mux CONNECT carries only disk-encryption +
// firewall, which are near-universally ON across an enterprise fleet (MDM/GPO) so the tier has ~no discriminating
// power; and — unlike the rule's configurable `risk_at_least` gate or the `device_trust_level` policy condition —
// it was a HIDDEN, non-configurable decision factor (a decision must not turn on something the operator cannot
// see or set). Security is preserved WITHOUT it by the rule's configurable risk gate (RiskSeverities, authored
// as risk_at_least): an operator who wants a high-risk device blocked from self-attesting laterally writes that
// rule, and one who wants posture to gate a rule uses the explicit `device_trust_level` policy condition.
func eastWestDeviceAttestationEligible(req model.DecisionRequest) bool {
	return req.TransportClientCertVerified && strings.TrimSpace(req.TransportDeviceIdentity) != ""
}

// eastWestDecisionFor resolves the east-west outcome for a request. Returns the decision value, reason,
// and reason codes to apply. Only called when EastWestEnabled and the request is an east-west protocol.
// An authenticate-mode hold is RELEASED to allow when a valid ephemeral grant matches (E3), or — on a rule
// that opts in — by device attestation for a machine/non-interactive flow (no human OOB possible).
func (e Evaluator) eastWestDecisionFor(req model.DecisionRequest, now time.Time) (decisionValue, reason string, reasonCodes []string, actions []model.DecisionAction) {
	rule, matched := MatchedEastWestRule(e.EastWestRules, req)
	mode := EastWestModeDeny
	if matched {
		switch m := strings.ToLower(strings.TrimSpace(rule.Mode)); m {
		case EastWestModeAllow, EastWestModeAuthenticate, EastWestModeDeny:
			mode = m
		default:
			mode = EastWestModeDeny // unknown mode = deny (fail closed)
		}
	}
	// Warn stage (learning-lifecycle dry-run): a matched authenticate/deny rule does NOT bite yet — the flow is
	// ALLOWED through, but a non-holding warn_notice action is emitted so the agent can surface a passive
	// "monitored; authentication will soon be required" message (coalesced once/session by the agent). Warn on an
	// allow rule is a no-op (nothing to soften), so it falls through to the normal allow below.
	if matched && rule.Warn && (mode == EastWestModeAuthenticate || mode == EastWestModeDeny) {
		return "allow",
			"East-west access permitted in Warn stage (monitored; enforcement not yet active).",
			[]string{"east_west_warn"},
			eastWestWarnActions(rule, req)
	}
	switch mode {
	case EastWestModeAllow:
		return "allow", "East-west access permitted by per-hop policy.", []string{"east_west_policy_allow"}, nil
	case EastWestModeAuthenticate:
		if e.hasValidEastWestGrant(req, now) {
			return "allow", "East-west access released by a valid ephemeral grant.", []string{"east_west_grant_satisfied"}, nil
		}
		// Device-attested auto (opt-in): a machine/non-interactive flow that cannot do an OOB ceremony is
		// allowed by its verified mTLS device identity + trusted posture, instead of holding forever.
		if rule.DeviceAttestedAuto && eastWestDeviceAttestationEligible(req) {
			return "allow", "East-west access allowed by device attestation (verified mTLS device + trusted posture).", []string{"east_west_device_attested"}, nil
		}
		// Carry the matched rule's step-up assurance (required IdP + phishing-resistant acr floor + freshness) on a
		// prompt_reauthentication action so the federated-auth gate requests the stronger factor AND rejects a
		// weaker (e.g. password acr=1) grant — authStepUpRequirements reads required_idp_id / min_acr from here.
		// Without this the east-west authenticate decision carried NO acr, so any presence-only grant satisfied it.
		return "authenticate_required", "East-west access requires interactive authentication.", []string{"east_west_authentication_required"}, eastWestStepUpActions(rule)
	default: // deny
		if matched {
			return "deny", "East-west access denied by per-hop policy.", []string{"east_west_policy_deny"}, nil
		}
		// Unmatched flow. In Partial Enforce (EastWestAllowUnmatched) the default is allow-all — enabled rules
		// bite, but a flow no rule covers is permitted (safe adoption before the terminal deny flip, S4). In Full
		// Enforce (the default) an unmatched flow is denied.
		if e.EastWestAllowUnmatched {
			return "allow", "East-west access permitted (Partial Enforce: no rule matched; unmatched default is allow-all).", []string{"east_west_unmatched_allow"}, nil
		}
		return "deny", "East-west access denied by default-deny per-hop policy.", []string{"east_west_default_deny"}, nil
	}
}

// eastWestStepUpActions builds the prompt_reauthentication action that carries an authenticate-mode east-west
// rule's required IdP + assurance floor to the enforcement gate. Empty fields are omitted (presence-only).
func eastWestStepUpActions(rule EastWestRule) []model.DecisionAction {
	meta := map[string]any{"east_west": true}
	if v := strings.TrimSpace(rule.RequiredIdPID); v != "" {
		meta["required_idp_id"] = v
	}
	if v := strings.TrimSpace(rule.MinACR); v != "" {
		meta["min_acr"] = v
	}
	if len(rule.RequiredAMR) > 0 {
		meta["required_amr"] = append([]string(nil), rule.RequiredAMR...)
	}
	a := model.DecisionAction{Type: "prompt_reauthentication", Metadata: meta}
	if rule.MaxAgeSeconds > 0 {
		a.TTLSeconds = intPtr(rule.MaxAgeSeconds)
	}
	return []model.DecisionAction{a}
}

// eastWestWarnActions builds the NON-HOLDING warn_notice action a Warn-stage rule emits alongside its allow. It
// tells the agent to surface a passive "this connection is monitored; authentication will soon be required" notice
// (the agent coalesces it once/session/resource). Unlike prompt_reauthentication it does NOT hold the flow — the
// decision is already allow — so the connection proceeds while the user is informed of the coming enforcement.
func eastWestWarnActions(rule EastWestRule, req model.DecisionRequest) []model.DecisionAction {
	meta := map[string]any{
		"east_west": true,
		"message":   "This internal connection is monitored. Authentication will soon be required to reach it.",
	}
	if v := strings.TrimSpace(req.Destination); v != "" {
		meta["destination"] = v
	}
	if v := strings.TrimSpace(req.ServiceFamily); v != "" {
		meta["service_family"] = v
	}
	if v := strings.TrimSpace(rule.ID); v != "" {
		meta["rule_id"] = v
	}
	return []model.DecisionAction{{Type: "warn_notice", Metadata: meta}}
}

// isEastWestFlow decides plane membership: an east-west PROTOCOL reaching a destination that is not the
// public internet.
//
// The protocol set is unchanged; what is added is the precondition the plane always implied and never
// checked. `IsEastWestProtocol` answers "is this a protocol lateral movement uses", which is not the same
// question as "is this flow lateral movement" — and treating the two as one held `ssh git@github.com` for an
// out-of-band ceremony and dropped it at two minutes, on a box whose operator reasonably read the stall as a
// broken network.
//
// A public destination falls through to the north-bound policy plane, which is not an exemption: that plane
// is where the internet-facing controls are, and it is the right place to govern SSH to the internet. Exfil
// over SSH is a real concern; it is simply not lateral movement.
func (e Evaluator) isEastWestFlow(req model.DecisionRequest) bool {
	return IsEastWestFlow(req, e.EastWestInternalNetworks)
}

// IsEastWestFlow is isEastWestFlow for callers outside the evaluator.
//
// It is exported because plane membership is decided in more than one place and those places MUST agree. The
// Edge's steer-mux path independently asked IsEastWestProtocol to decide which adoption queue a flow belongs
// in: the east-west observe inventory, or the egress policy-candidate capture (which explicitly EXCLUDES
// east-west protocols so one flow cannot land in two queues that adopt into different planes). Narrowing only
// the evaluator would have left `ssh git@github.com` decided on the north-bound plane while still being
// recorded as lateral AND still excluded from the egress queue — in neither queue, which is worse than the
// wrong one. One predicate, so the decision and the record cannot disagree about what a flow is.
func IsEastWestFlow(req model.DecisionRequest, declared InternalNetworks) bool {
	if !IsEastWestProtocol(req.ServiceFamily) {
		return false
	}
	return EastWestLocalityAdmits(ClassifyDestinationLocality(req, declared))
}
