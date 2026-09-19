package eastwest

import (
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/policy"
)

// admin_east_west: control-plane for east-west (internal/lateral) per-hop authorization (E1.5). Admins
// enable east-west enforcement and set rules ((source x destination x protocol) -> allow/authenticate/
// deny); changes hot-apply to the live decision path via the policy store + RuntimeEvaluator, no restart.

type adminStore interface {
	SetEastWestEnabled(tenantID string, enabled bool)
	EastWestIsEnabled(tenantID string) bool
	SetEastWestAllowUnmatched(tenantID string, allow bool)
	EastWestAllowsUnmatched(tenantID string) bool
	SetEastWestRules(tenantID string, rules []decision.EastWestRule)
	EastWestRulesFor(tenantID string) []decision.EastWestRule
	SetEastWestMaxGrantTTL(tenantID string, seconds int)
	EastWestMaxGrantTTL(tenantID string) int
}

// The east-west learning-lifecycle posture is a 3-state ramp over two flags (enabled, allowUnmatched):
//
//	observe — enabled=false: the layer is inert (allow-all, watch + log only). No rule bites.
//	partial — enabled=true,  allowUnmatched=true:  enabled rules bite, but a flow matching NO rule is ALLOWED.
//	full    — enabled=true,  allowUnmatched=false: enabled rules bite, and an unmatched flow is DENIED.
//
// Full is the terminal state; the operator ramps observe → partial → full as the observed flows converge.
const (
	ModeObserve = "observe"
	ModePartial = "partial"
	ModeFull    = "full"
)

// modeFor derives the posture name from the two flags.
func modeFor(enabled, allowUnmatched bool) string {
	if !enabled {
		return ModeObserve
	}
	if allowUnmatched {
		return ModePartial
	}
	return ModeFull
}

type adminRule struct {
	ID           string   `json:"id"`
	Priority     int      `json:"priority"`
	SourceUsers  []string `json:"source_users"`
	SourceGroups []string `json:"source_groups"`
	Destinations []string `json:"destinations"`
	Protocols    []string `json:"protocols"`
	Mode         string   `json:"mode"`
	// MaxTTLSeconds caps grants issued for this rule (E6 sensitivity tiering). 0 = no per-rule cap.
	MaxTTLSeconds int `json:"max_ttl_seconds"`
	// DeviceAttestedAuto (default false): allow a machine/non-interactive (user-less, OOB-incapable) flow on
	// this authenticate rule by device attestation — verified mTLS device identity + trusted posture — instead
	// of holding. Opt-in per destination/protocol where device-attested lateral is acceptable.
	DeviceAttestedAuto bool `json:"device_attested_auto"`
}

type adminStatusResponse struct {
	SchemaVersion  string `json:"schema_version"`
	TenantID       string `json:"tenant_id"`
	Enabled        bool   `json:"east_west_enabled"`
	AllowUnmatched bool   `json:"east_west_allow_unmatched"`
	// Mode is the derived learning-lifecycle posture: observe | partial | full (see modeFor). It is the field the
	// Console drives; Enabled/AllowUnmatched are the underlying flags.
	Mode                string      `json:"mode"`
	Rules               []adminRule `json:"rules"`
	MaxGrantTTLSeconds  int         `json:"max_grant_ttl_seconds"`
	NoSecretAttestation bool        `json:"no_secret_attestation"`
}

type AdminUpdateRequest struct {
	// Mode, when present, sets the whole posture atomically (observe|partial|full) — the preferred control. It
	// takes precedence over Enabled. Enabled (legacy) toggles enforcement observe<->full only. Rules, when
	// present, REPLACES the whole rule set. MaxGrantTTLSeconds sets the per-tenant grant TTL ceiling (0 = no cap).
	Mode               *string      `json:"mode"`
	Enabled            *bool        `json:"enabled"`
	Rules              *[]adminRule `json:"rules"`
	MaxGrantTTLSeconds *int         `json:"max_grant_ttl_seconds"`
}

func adminRuleFromModel(r decision.EastWestRule) adminRule {
	return adminRule{
		ID: r.ID, Priority: r.Priority, SourceUsers: r.SourceUsers, SourceGroups: r.SourceGroups,
		Destinations: r.Destinations, Protocols: r.Protocols, Mode: r.Mode, MaxTTLSeconds: r.MaxTTLSeconds,
		DeviceAttestedAuto: r.DeviceAttestedAuto,
	}
}

func adminRuleToModel(r adminRule) (decision.EastWestRule, error) {
	mode := strings.ToLower(strings.TrimSpace(r.Mode))
	switch mode {
	case decision.EastWestModeAllow, decision.EastWestModeAuthenticate, decision.EastWestModeDeny:
	default:
		return decision.EastWestRule{}, fmt.Errorf("invalid mode %q (want allow|authenticate|deny)", r.Mode)
	}
	for _, p := range r.Protocols {
		if !decision.IsEastWestProtocol(p) {
			return decision.EastWestRule{}, fmt.Errorf("protocol %q is not an east-west protocol", p)
		}
	}
	return decision.EastWestRule{
		ID: strings.TrimSpace(r.ID), Priority: r.Priority,
		SourceUsers: r.SourceUsers, SourceGroups: r.SourceGroups,
		Destinations: r.Destinations, Protocols: r.Protocols, Mode: mode, MaxTTLSeconds: r.MaxTTLSeconds,
		DeviceAttestedAuto: r.DeviceAttestedAuto,
	}, nil
}

func AdminStatus(store policy.RuntimeStore, tenantID string) adminStatusResponse {
	resp := adminStatusResponse{
		SchemaVersion:       "admin_east_west_status.v1",
		TenantID:            tenantID,
		Rules:               []adminRule{},
		NoSecretAttestation: true,
	}
	s, ok := store.(adminStore)
	if !ok {
		return resp
	}
	resp.Enabled = s.EastWestIsEnabled(tenantID)
	resp.AllowUnmatched = s.EastWestAllowsUnmatched(tenantID)
	resp.Mode = modeFor(resp.Enabled, resp.AllowUnmatched)
	resp.MaxGrantTTLSeconds = s.EastWestMaxGrantTTL(tenantID)
	for _, r := range s.EastWestRulesFor(tenantID) {
		resp.Rules = append(resp.Rules, adminRuleFromModel(r))
	}
	return resp
}

// ApplyAdminUpdate toggles enforcement and/or replaces the rule set for a tenant, hot-applied to
// the live decision path. Returns the resulting status.
func ApplyAdminUpdate(store policy.RuntimeStore, tenantID string, req AdminUpdateRequest) (adminStatusResponse, error) {
	s, ok := store.(interface {
		ApplyEastWestUpdateConfirmed(string, *[]decision.EastWestRule, *int, *bool, *bool) error
	})
	if !ok {
		return adminStatusResponse{}, policy.ErrPolicyPersistence
	}
	var rules *[]decision.EastWestRule
	if req.Rules != nil {
		parsed := make([]decision.EastWestRule, 0, len(*req.Rules))
		for i, raw := range *req.Rules {
			rule, err := adminRuleToModel(raw)
			if err != nil {
				return adminStatusResponse{}, fmt.Errorf("rule[%d]: %w", i, err)
			}
			parsed = append(parsed, rule)
		}
		rules = &parsed
	}
	enabled, unmatched := req.Enabled, (*bool)(nil)
	if req.Mode != nil {
		e, u := false, false
		switch strings.ToLower(strings.TrimSpace(*req.Mode)) {
		case ModeObserve:
			enabled = &e
		case ModePartial:
			e, u = true, true
			enabled, unmatched = &e, &u
		case ModeFull:
			e = true
			enabled, unmatched = &e, &u
		default:
			return adminStatusResponse{}, fmt.Errorf("invalid mode %q (want observe|partial|full)", *req.Mode)
		}
	} else if enabled != nil && *enabled {
		u := false
		unmatched = &u
	}
	if err := s.ApplyEastWestUpdateConfirmed(tenantID, rules, req.MaxGrantTTLSeconds, enabled, unmatched); err != nil {
		return adminStatusResponse{}, err
	}
	return AdminStatus(store, tenantID), nil
}
