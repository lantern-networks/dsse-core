package decision

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func eastWestEvaluator(enabled bool, rules ...EastWestRule) Evaluator {
	return Evaluator{
		PolicyBundle:    model.PolicyBundle{ID: "pb_test", TenantID: "tenant_test"},
		EastWestEnabled: enabled,
		EastWestRules:   rules,
	}
}

func eastWestRequest(user, dest, family string, groups ...string) model.DecisionRequest {
	return model.DecisionRequest{
		TenantID:      "tenant_test",
		UserID:        user,
		UserGroups:    groups,
		Destination:   dest,
		ServiceFamily: family,
		ActorType:     "human",
	}
}

func TestEastWestDisabledIsInert(t *testing.T) {
	// With east-west disabled, an ssh request hits the normal path -> default no_policy_match deny,
	// NOT an east-west decision. (Byte-identical legacy behaviour.)
	e := eastWestEvaluator(false)
	dec := e.Evaluate(eastWestRequest("u1", "server-b", "ssh"))
	if dec.PolicyID == "east_west_policy" {
		t.Fatalf("east-west disabled must not produce an east-west decision; got policy %s", dec.PolicyID)
	}
	for _, c := range dec.ReasonCodes {
		if c == "east_west_default_deny" || c == "east_west_policy_deny" || c == "east_west_policy_allow" {
			t.Fatalf("east-west disabled leaked an east-west reason code: %v", dec.ReasonCodes)
		}
	}
}

func TestEastWestDefaultDeny(t *testing.T) {
	// Enabled, no matching rule -> default-deny east-west.
	e := eastWestEvaluator(true)
	dec := e.Evaluate(eastWestRequest("u1", "server-b", "rdp"))
	if dec.Decision != "deny" {
		t.Fatalf("unmatched east-west must deny; got %s", dec.Decision)
	}
	if !hasReasonCode(dec.ReasonCodes, "east_west_default_deny") {
		t.Fatalf("expected east_west_default_deny; got %v", dec.ReasonCodes)
	}
}

func TestEastWestNonEastWestProtocolUnaffected(t *testing.T) {
	// Enabled, but an https request is NOT east-west -> must not be governed by east-west default-deny.
	e := eastWestEvaluator(true)
	dec := e.Evaluate(eastWestRequest("u1", "example.com", "https"))
	if dec.PolicyID == "east_west_policy" {
		t.Fatalf("non-east-west protocol must not hit east-west layer; got policy %s", dec.PolicyID)
	}
}

func TestEastWestAllowRule(t *testing.T) {
	e := eastWestEvaluator(true, EastWestRule{
		ID: "r-allow", Priority: 10,
		SourceUsers: []string{"u1"}, Destinations: []string{"server-b"}, Protocols: []string{"ssh"},
		Mode: EastWestModeAllow,
	})
	dec := e.Evaluate(eastWestRequest("u1", "server-b", "ssh"))
	if dec.Decision != "allow" || !hasReasonCode(dec.ReasonCodes, "east_west_policy_allow") {
		t.Fatalf("expected allow/east_west_policy_allow; got %s %v", dec.Decision, dec.ReasonCodes)
	}
	// A different user to the same destination has no rule -> default-deny (per-hop, identity-bound).
	other := e.Evaluate(eastWestRequest("u2", "server-b", "ssh"))
	if other.Decision != "deny" || !hasReasonCode(other.ReasonCodes, "east_west_default_deny") {
		t.Fatalf("non-selected identity must default-deny; got %s %v", other.Decision, other.ReasonCodes)
	}
}

func TestEastWestAuthenticateRule(t *testing.T) {
	e := eastWestEvaluator(true, EastWestRule{
		ID: "r-auth", Priority: 10,
		SourceGroups: []string{"admins"}, Destinations: []string{"dc-01"}, Protocols: []string{"smb", "rdp"},
		Mode: EastWestModeAuthenticate,
	})
	dec := e.Evaluate(eastWestRequest("u9", "dc-01", "rdp", "admins"))
	if dec.Decision != "authenticate_required" || !hasReasonCode(dec.ReasonCodes, "east_west_authentication_required") {
		t.Fatalf("expected authenticate_required; got %s %v", dec.Decision, dec.ReasonCodes)
	}
}

func TestEastWestExplicitDenyRule(t *testing.T) {
	e := eastWestEvaluator(true, EastWestRule{
		ID: "r-deny", Priority: 10,
		Destinations: []string{"server-b"}, Protocols: []string{"smb"},
		Mode: EastWestModeDeny,
	})
	dec := e.Evaluate(eastWestRequest("u1", "server-b", "smb"))
	if dec.Decision != "deny" || !hasReasonCode(dec.ReasonCodes, "east_west_policy_deny") {
		t.Fatalf("expected explicit east_west_policy_deny; got %s %v", dec.Decision, dec.ReasonCodes)
	}
}

func TestEastWestPartialEnforceUnmatchedAllow(t *testing.T) {
	// Partial Enforce (S4): enabled rules bite, but a flow matching NO rule is ALLOWED (allow-all default), not
	// default-denied. An explicit deny rule STILL denies (rules always bite).
	e := eastWestEvaluator(true, EastWestRule{
		ID: "r-deny", Priority: 10, Destinations: []string{"dc-01"}, Protocols: []string{"smb"}, Mode: EastWestModeDeny,
	})
	e.EastWestAllowUnmatched = true

	// Unmatched flow (no rule for server-x) → allowed under Partial, with the distinct reason code.
	un := e.Evaluate(eastWestRequest("u1", "server-x", "ssh"))
	if un.Decision != "allow" || !hasReasonCode(un.ReasonCodes, "east_west_unmatched_allow") {
		t.Fatalf("partial: unmatched must allow with east_west_unmatched_allow; got %s %v", un.Decision, un.ReasonCodes)
	}
	if hasReasonCode(un.ReasonCodes, "east_west_default_deny") {
		t.Fatalf("partial: unmatched must NOT default-deny")
	}
	// A matched deny rule still bites in Partial.
	den := e.Evaluate(eastWestRequest("u1", "dc-01", "smb"))
	if den.Decision != "deny" || !hasReasonCode(den.ReasonCodes, "east_west_policy_deny") {
		t.Fatalf("partial: an explicit deny rule must still deny; got %s %v", den.Decision, den.ReasonCodes)
	}
}

func TestEastWestFullEnforceUnmatchedDeny(t *testing.T) {
	// Full Enforce (default, AllowUnmatched=false): an unmatched flow is default-denied — the terminal state.
	e := eastWestEvaluator(true)
	dec := e.Evaluate(eastWestRequest("u1", "server-x", "ssh"))
	if dec.Decision != "deny" || !hasReasonCode(dec.ReasonCodes, "east_west_default_deny") {
		t.Fatalf("full: unmatched must default-deny; got %s %v", dec.Decision, dec.ReasonCodes)
	}
}

func warnNoticeAction(dec model.AccessDecision) (model.DecisionAction, bool) {
	for _, a := range dec.Actions {
		if a.Type == "warn_notice" {
			return a, true
		}
	}
	return model.DecisionAction{}, false
}

func TestEastWestWarnStageSoftensAuthenticate(t *testing.T) {
	// A Warn-stage authenticate rule does NOT hold the flow — it ALLOWS it and emits a non-holding warn_notice.
	e := eastWestEvaluator(true, EastWestRule{
		ID: "r-warn", Priority: 10,
		SourceGroups: []string{"admins"}, Destinations: []string{"dc-01"}, Protocols: []string{"rdp"},
		Mode: EastWestModeAuthenticate, Warn: true,
	})
	dec := e.Evaluate(eastWestRequest("u9", "dc-01", "rdp", "admins"))
	if dec.Decision != "allow" {
		t.Fatalf("warn stage must allow (non-holding), got %s", dec.Decision)
	}
	if !hasReasonCode(dec.ReasonCodes, "east_west_warn") {
		t.Fatalf("expected east_west_warn; got %v", dec.ReasonCodes)
	}
	if hasReasonCode(dec.ReasonCodes, "east_west_authentication_required") {
		t.Fatalf("warn stage must NOT emit authenticate_required")
	}
	a, ok := warnNoticeAction(dec)
	if !ok {
		t.Fatalf("expected a warn_notice action; actions=%#v", dec.Actions)
	}
	if a.Metadata["destination"] != "dc-01" || a.Metadata["service_family"] != "rdp" || a.Metadata["rule_id"] != "r-warn" {
		t.Fatalf("warn_notice metadata missing/wrong: %#v", a.Metadata)
	}
}

func TestEastWestWarnStageSoftensDeny(t *testing.T) {
	// A Warn-stage deny rule also softens to allow-with-notice (dry-run before the deny bites).
	e := eastWestEvaluator(true, EastWestRule{
		ID: "r-warn-deny", Priority: 10,
		Destinations: []string{"server-b"}, Protocols: []string{"smb"},
		Mode: EastWestModeDeny, Warn: true,
	})
	dec := e.Evaluate(eastWestRequest("u1", "server-b", "smb"))
	if dec.Decision != "allow" || !hasReasonCode(dec.ReasonCodes, "east_west_warn") {
		t.Fatalf("warn+deny must allow with east_west_warn; got %s %v", dec.Decision, dec.ReasonCodes)
	}
	if _, ok := warnNoticeAction(dec); !ok {
		t.Fatalf("expected warn_notice action")
	}
}

func TestEastWestWarnOnAllowIsNoop(t *testing.T) {
	// Warn on an ALLOW rule has nothing to soften — the outcome is an ordinary allow, no warn_notice.
	e := eastWestEvaluator(true, EastWestRule{
		ID: "r-allow-warn", Priority: 10,
		SourceUsers: []string{"u1"}, Destinations: []string{"server-b"}, Protocols: []string{"ssh"},
		Mode: EastWestModeAllow, Warn: true,
	})
	dec := e.Evaluate(eastWestRequest("u1", "server-b", "ssh"))
	if dec.Decision != "allow" || !hasReasonCode(dec.ReasonCodes, "east_west_policy_allow") {
		t.Fatalf("warn on allow should be an ordinary allow; got %s %v", dec.Decision, dec.ReasonCodes)
	}
	if _, ok := warnNoticeAction(dec); ok {
		t.Fatalf("warn on an allow rule must NOT emit a warn_notice")
	}
}

func TestEastWestLowerPriorityNumberWins(t *testing.T) {
	// Precedence is LOWER-priority-number-wins — the same contract as the egress plane and the Console
	// "Priority (lower wins)" label. The rule with the lower number is evaluated first and wins.
	e := eastWestEvaluator(true,
		EastWestRule{ID: "winner", Priority: 1, Destinations: []string{"server-b"}, Protocols: []string{"ssh"}, Mode: EastWestModeDeny},
		EastWestRule{ID: "loser", Priority: 100, Destinations: []string{"server-b"}, Protocols: []string{"ssh"}, Mode: EastWestModeAllow},
	)
	dec := e.Evaluate(eastWestRequest("u1", "server-b", "ssh"))
	if dec.Decision != "deny" {
		t.Fatalf("the lower priority NUMBER must win (lower-wins, matching egress + GUI); got %s", dec.Decision)
	}
}

func TestEastWestGrantReleasesAuthenticateHold(t *testing.T) {
	base := eastWestEvaluator(true, EastWestRule{
		ID: "r-auth", Priority: 10, Destinations: []string{"dc-01"}, Protocols: []string{"rdp"}, Mode: EastWestModeAuthenticate,
	})
	req := eastWestRequest("u9", "dc-01", "rdp")
	req.DeviceID = "dev1"

	// No grant -> hold.
	if dec := base.Evaluate(req); dec.Decision != "authenticate_required" {
		t.Fatalf("without grant expected authenticate_required; got %s", dec.Decision)
	}

	// A valid matching grant -> released to allow.
	withGrant := base
	withGrant.EastWestGrants = []EastWestGrant{{
		SubjectUserID: "u9", DeviceID: "dev1", Destination: "dc-01", Protocol: "rdp",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	dec := withGrant.Evaluate(req)
	if dec.Decision != "allow" || !hasReasonCode(dec.ReasonCodes, "east_west_grant_satisfied") {
		t.Fatalf("valid grant must release to allow; got %s %v", dec.Decision, dec.ReasonCodes)
	}

	// Expired grant -> still held.
	expired := base
	expired.EastWestGrants = []EastWestGrant{{
		SubjectUserID: "u9", DeviceID: "dev1", Destination: "dc-01", Protocol: "rdp",
		ExpiresAt: time.Now().Add(-time.Minute),
	}}
	if dec := expired.Evaluate(req); dec.Decision != "authenticate_required" {
		t.Fatalf("expired grant must not release; got %s", dec.Decision)
	}

	// Grant for a different device -> not released (per-hop device binding).
	otherDevice := base
	otherDevice.EastWestGrants = []EastWestGrant{{
		SubjectUserID: "u9", DeviceID: "dev2", Destination: "dc-01", Protocol: "rdp",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	if dec := otherDevice.Evaluate(req); dec.Decision != "authenticate_required" {
		t.Fatalf("grant for another device must not release; got %s", dec.Decision)
	}
}

// P1a (real-AD finding): a WFP-steered lateral flow carries only a DEVICE identity (mTLS), no user
// (subject_user_id=null). This locks the resolution: such a flow holds by default (fail-closed — correct for
// non-interactive/machine-account lateral, which cannot complete an OOB user ceremony), but a DEVICE-ATTESTED
// grant (SubjectUserID empty + DeviceID set) releases it — so machine flows are served by a posture-attested
// device-bound grant with no human, not by an impossible interactive ceremony.
func TestEastWestDeviceAttestedGrantReleasesUserlessFlow(t *testing.T) {
	// Authenticate rule with a WILDCARD source (no SourceUsers/Groups) — the only kind that matches a
	// user-less WFP device flow.
	base := eastWestEvaluator(true, EastWestRule{
		ID: "r-auth-wild", Priority: 10, Destinations: []string{"10.10.0.10"}, Protocols: []string{"smb"},
		Mode: EastWestModeAuthenticate,
	})
	// Real WFP steer: no user AND no client DeviceID — only the AUTHORITATIVE transport device identity
	// (set by the mTLS (T) handshake) is present.
	req := eastWestRequest("", "10.10.0.10", "smb") // user-less (UserID="" / SubjectUserID="")
	req.DeviceID = ""
	req.TransportDeviceIdentity = "win-dev-1"

	// Default (no grant): user-less flow holds = fail-closed. This is the safe machine-account behavior.
	if dec := base.Evaluate(req); dec.Decision != "authenticate_required" {
		t.Fatalf("user-less flow without a grant must hold (fail-closed); got %s", dec.Decision)
	}

	// Device-attested grant (no user, bound to the transport identity) releases the user-less steered hold.
	dev := base
	dev.EastWestGrants = []EastWestGrant{{
		SubjectUserID: "", DeviceID: "win-dev-1", Destination: "10.10.0.10", Protocol: "smb",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	if dec := dev.Evaluate(req); dec.Decision != "allow" || !hasReasonCode(dec.ReasonCodes, "east_west_grant_satisfied") {
		t.Fatalf("device-attested (user-less) grant must release the hold; got %s %v", dec.Decision, dec.ReasonCodes)
	}

	// Per-hop device binding still holds: a device-attested grant for ANOTHER device must not release.
	other := base
	other.EastWestGrants = []EastWestGrant{{
		SubjectUserID: "", DeviceID: "win-dev-2", Destination: "10.10.0.10", Protocol: "smb",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	if dec := other.Evaluate(req); dec.Decision != "authenticate_required" {
		t.Fatalf("device-attested grant for another device must not release; got %s", dec.Decision)
	}
}

// Review #7 (grant borrow by DeviceID spoof): when a flow carries an AUTHORITATIVE transport identity, the
// client-claimed DeviceID must be IGNORED for grant matching — a flow whose mTLS identity is win-dev-2
// claiming DeviceID=win-dev-1 in its request body must NOT borrow win-dev-1's grant, and the same claim must
// not satisfy a source-device rule selector.
func TestEastWestClaimedDeviceIDCannotBorrowGrantOrSourceSelector(t *testing.T) {
	base := eastWestEvaluator(true, EastWestRule{
		ID: "r-auth", Priority: 10, Destinations: []string{"10.10.0.10"}, Protocols: []string{"smb"},
		Mode: EastWestModeAuthenticate,
	})
	base.EastWestGrants = []EastWestGrant{{
		SubjectUserID: "", DeviceID: "win-dev-1", Destination: "10.10.0.10", Protocol: "smb",
		ExpiresAt: time.Now().Add(time.Hour),
	}}

	// Spoof: transport identity is win-dev-2, request body claims win-dev-1. Must stay held.
	spoof := eastWestRequest("", "10.10.0.10", "smb")
	spoof.TransportDeviceIdentity = "win-dev-2"
	spoof.DeviceID = "win-dev-1"
	if dec := base.Evaluate(spoof); dec.Decision != "authenticate_required" {
		t.Fatalf("claimed DeviceID must not borrow another device's grant; got %s %v", dec.Decision, dec.ReasonCodes)
	}

	// The legitimate holder (transport identity win-dev-1) is still released.
	legit := eastWestRequest("", "10.10.0.10", "smb")
	legit.TransportDeviceIdentity = "win-dev-1"
	if dec := base.Evaluate(legit); dec.Decision != "allow" || !hasReasonCode(dec.ReasonCodes, "east_west_grant_satisfied") {
		t.Fatalf("transport-identity holder must be released; got %s %v", dec.Decision, dec.ReasonCodes)
	}

	// A transportless request still matches by claim (no authoritative identity exists to prefer).
	claimOnly := eastWestRequest("", "10.10.0.10", "smb")
	claimOnly.DeviceID = "win-dev-1"
	if dec := base.Evaluate(claimOnly); dec.Decision != "allow" {
		t.Fatalf("claimed-ID fallback without a transport identity must still release; got %s", dec.Decision)
	}

	// Source-device selector: an allow rule scoped to win-dev-1 must not match the spoofing flow either.
	scoped := eastWestEvaluator(true, EastWestRule{
		ID: "r-dev-allow", Priority: 5, SourceDevices: []string{"win-dev-1"},
		Destinations: []string{"10.10.0.20"}, Protocols: []string{"smb"}, Mode: EastWestModeAllow,
	})
	spoofSel := eastWestRequest("", "10.10.0.20", "smb")
	spoofSel.TransportDeviceIdentity = "win-dev-2"
	spoofSel.DeviceID = "win-dev-1"
	if dec := scoped.Evaluate(spoofSel); dec.Decision == "allow" {
		t.Fatalf("claimed DeviceID must not satisfy a source-device selector; got %s", dec.Decision)
	}
	legitSel := eastWestRequest("", "10.10.0.20", "smb")
	legitSel.TransportDeviceIdentity = "win-dev-1"
	if dec := scoped.Evaluate(legitSel); dec.Decision != "allow" {
		t.Fatalf("transport-identity holder must match the source-device selector; got %s", dec.Decision)
	}
}

// Device-attested AUTO (no admin pre-issue): an authenticate rule that opts in (DeviceAttestedAuto) allows a
// machine/non-interactive flow by device attestation — a VERIFIED, enrolled mTLS device identity — instead of
// holding for an impossible OOB ceremony. Eligibility does NOT gate on posture (a hidden, non-configurable, and
// in practice near-universal signal); security is preserved by the high-risk overlay + the configurable risk
// gate. Default off keeps machine flows fail-closed.
func TestEastWestDeviceAttestedAuto(t *testing.T) {
	withAttest := eastWestEvaluator(true, EastWestRule{
		ID: "r-attest", Priority: 10, Destinations: []string{"10.10.0.10"}, Protocols: []string{"smb"},
		Mode: EastWestModeAuthenticate, DeviceAttestedAuto: true,
	})
	// Eligible: verified enrolled mTLS device identity, user-less — allowed by attestation.
	elig := eastWestRequest("", "10.10.0.10", "smb")
	elig.TransportClientCertVerified = true
	elig.TransportDeviceIdentity = "win-dev-1"
	elig.DeviceTrustLevel = "managed"
	if dec := withAttest.Evaluate(elig); dec.Decision != "allow" || !hasReasonCode(dec.ReasonCodes, "east_west_device_attested") {
		t.Fatalf("eligible device-attested flow must be allowed; got %s %v", dec.Decision, dec.ReasonCodes)
	}

	// Not eligible — no verified mTLS device -> fail-closed (hold).
	noCert := elig
	noCert.TransportClientCertVerified = false
	if dec := withAttest.Evaluate(noCert); dec.Decision != "authenticate_required" {
		t.Fatalf("flow without a verified mTLS device must hold; got %s", dec.Decision)
	}
	// Posture does NOT gate device attestation (removed as a hidden, non-configurable, near-universal factor): a
	// verified enrolled device with a "noncompliant" posture tier is STILL device-attested. If an operator wants
	// posture to gate a rule, that is the explicit device_trust_level policy condition — not this hidden tier.
	lowPosture := elig
	lowPosture.DeviceTrustLevel = "noncompliant"
	if dec := withAttest.Evaluate(lowPosture); dec.Decision != "allow" || !hasReasonCode(dec.ReasonCodes, "east_west_device_attested") {
		t.Fatalf("posture must NOT gate device attestation; a verified device should still be allowed, got %s %v", dec.Decision, dec.ReasonCodes)
	}
	// Security preserved by RISK — but by an OPERATOR-AUTHORED risk gate, not by an automatic block. Risk alone
	// must not deny: with no risk-gated rule the attested flow is still allowed, because the product does not
	// detect-and-block on its own (the hardcoded overlay that used to deny here was removed).
	highRisk := elig
	highRisk.AdminHighRisk = true
	highRisk.RiskStateSeverity = "high"
	if dec := withAttest.Evaluate(highRisk); dec.Decision != "allow" {
		t.Fatalf("risk alone must not deny — authorization is the policy's job; got %s", dec.Decision)
	}
	// With a risk-gated rule authored, the SAME flow is denied: a compromised (EDR-marked) enrolled machine
	// cannot self-attest laterally, because the operator said so.
	gated := eastWestEvaluator(true,
		EastWestRule{
			ID: "r-deny-high-risk", Priority: 5, Destinations: []string{"10.10.0.10"}, Protocols: []string{"smb"},
			Mode: EastWestModeDeny, RiskSeverities: []string{"high", "critical"},
		},
		EastWestRule{
			ID: "r-attest", Priority: 10, Destinations: []string{"10.10.0.10"}, Protocols: []string{"smb"},
			Mode: EastWestModeAuthenticate, DeviceAttestedAuto: true,
		},
	)
	if dec := gated.Evaluate(highRisk); dec.Decision != "deny" {
		t.Fatalf("an authored risk-gated deny must bite at high risk; got %s", dec.Decision)
	}
	// ...and the same authored rule set leaves a LOW-risk attested flow alone.
	if dec := gated.Evaluate(elig); dec.Decision != "allow" {
		t.Fatalf("the risk gate must not affect a low-risk flow; got %s", dec.Decision)
	}

	// Opt-in only: a plain authenticate rule (no DeviceAttestedAuto) must NOT auto-allow even an eligible
	// device — machine flows stay fail-closed unless a rule explicitly opts in.
	noOptIn := eastWestEvaluator(true, EastWestRule{
		ID: "r-plain", Priority: 10, Destinations: []string{"10.10.0.10"}, Protocols: []string{"smb"},
		Mode: EastWestModeAuthenticate,
	})
	if dec := noOptIn.Evaluate(elig); dec.Decision != "authenticate_required" {
		t.Fatalf("without opt-in an eligible device must still hold (no auto-allow); got %s", dec.Decision)
	}
}

func TestEastWestGrantDoesNotOverrideDeny(t *testing.T) {
	// A grant releases an authenticate hold, never an explicit/default deny.
	e := eastWestEvaluator(true, EastWestRule{
		ID: "r-deny", Priority: 10, Destinations: []string{"dc-01"}, Protocols: []string{"smb"}, Mode: EastWestModeDeny,
	})
	e.EastWestGrants = []EastWestGrant{{Destination: "dc-01", Protocol: "smb", ExpiresAt: time.Now().Add(time.Hour)}}
	req := eastWestRequest("u9", "dc-01", "smb")
	if dec := e.Evaluate(req); dec.Decision != "deny" {
		t.Fatalf("a grant must not override an explicit deny; got %s", dec.Decision)
	}
}

func TestEastWestGrantIdleExpiry(t *testing.T) {
	base := eastWestEvaluator(true, EastWestRule{
		ID: "r", Priority: 10, Destinations: []string{"dc-01"}, Protocols: []string{"rdp"}, Mode: EastWestModeAuthenticate,
	})
	req := eastWestRequest("u9", "dc-01", "rdp")
	req.DeviceID = "dev1"
	now := time.Now()
	bind := EastWestGrant{SubjectUserID: "u9", DeviceID: "dev1", Destination: "dc-01", Protocol: "rdp", ExpiresAt: now.Add(time.Hour), IdleTTLSeconds: 60}

	// Idle beyond the window (last used 10 min ago, idle ttl 60s) -> not released.
	idle := base
	bIdle := bind
	bIdle.LastUsedAt = now.Add(-10 * time.Minute)
	idle.EastWestGrants = []EastWestGrant{bIdle}
	if dec := idle.Evaluate(req); dec.Decision != "authenticate_required" {
		t.Fatalf("idle-expired grant must not release; got %s", dec.Decision)
	}

	// Recently used -> released.
	fresh := base
	bFresh := bind
	bFresh.LastUsedAt = now
	fresh.EastWestGrants = []EastWestGrant{bFresh}
	if dec := fresh.Evaluate(req); dec.Decision != "allow" {
		t.Fatalf("fresh grant within idle window must release; got %s", dec.Decision)
	}
}

func hasReasonCode(codes []string, want string) bool {
	for _, c := range codes {
		if c == want {
			return true
		}
	}
	return false
}
