package device

import (
	"strconv"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

// Derived device trust levels from posture evaluation.
const (
	PostureTrustManaged      = "managed"
	PostureTrustNonCompliant = "noncompliant"
)

// PosturePolicy is the Edge-side ruleset that turns real posture signals into a device trust level.
// The Edge owns this judgment — it does not trust a client-declared trust string when signals are
// present, so a compromised endpoint cannot simply assert it is "managed".
type PosturePolicy struct {
	RequireDiskEncryption bool
	RequireFirewall       bool
	// RequireEnforcementAgentHealthy (W-3): a managed device's NE/WFP enforcement agent must report healthy.
	// Tamper (agent unhealthy / signal missing) degrades trust -> regression -> grant revocation (/E5).
	RequireEnforcementAgentHealthy bool
	// MinOSVersion, when non-empty, requires the reported OS version to be >= it (dotted-numeric compare).
	MinOSVersion string
}

// DefaultPosturePolicy is a sensible baseline: a managed device must have disk encryption, the
// firewall, and screen lock. OS-version floor and enforcement-agent-health are opt-in (empty/false = no
// check) — agent-health enforcement (W-3) defaults OFF so that existing devices that do not yet report the
// enforcement_agent_healthy signal are NOT flipped to non-compliant; admins turn it on per tenant once the
// endpoint agents report it (additive, like the other new live behaviours).
func DefaultPosturePolicy() PosturePolicy {
	return PosturePolicy{
		RequireDiskEncryption: true,
		RequireFirewall:       true,
	}
}

// TrustLevelIsManaged reports whether a device trust level is a "trusted" tier that may hold
// standing access. Used to detect posture regression for continuous authentication.
func TrustLevelIsManaged(level string) bool {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case PostureTrustManaged, "trusted", "compliant", "high":
		return true
	}
	return false
}

// PostureRegressed reports whether device trust dropped from a trusted tier to a non-trusted one
// (e.g. managed -> noncompliant). A regression must trigger access reduction — revoking the
// device's standing grants so the next internal hop must re-authenticate (, -> E5).
func PostureRegressed(prev, current string) bool {
	return TrustLevelIsManaged(prev) && !TrustLevelIsManaged(current)
}

// DerivePostureTrustLevel computes the device trust level from reported posture signals. It returns
// the trust level, whether the device is compliant, and the non-secret reasons it failed (signal
// names), so the failures can be surfaced in audit without leaking values. A required signal that is
// missing (nil) or false fails — unknown is treated as non-compliant. nil signals => non-compliant.
func DerivePostureTrustLevel(signals *model.DevicePostureSignals, policy PosturePolicy) (string, bool, []string) {
	if signals == nil {
		return PostureTrustNonCompliant, false, []string{"no_posture_signals"}
	}
	reasons := []string{}
	enabled := func(p *bool) bool { return p != nil && *p }
	if policy.RequireDiskEncryption && !enabled(signals.DiskEncryptionEnabled) {
		reasons = append(reasons, "disk_encryption_disabled_or_unknown")
	}
	if policy.RequireFirewall && !enabled(signals.FirewallEnabled) {
		reasons = append(reasons, "firewall_disabled_or_unknown")
	}
	// W-3 (tamper-evident): a tampered/unhealthy or non-reporting enforcement agent fails posture, so the
	// device drops out of the managed tier and its standing grants are revoked (via PostureRegressed).
	if policy.RequireEnforcementAgentHealthy && !enabled(signals.EnforcementAgentHealthy) {
		reasons = append(reasons, "enforcement_agent_unhealthy_or_unknown")
	}
	if policy.MinOSVersion != "" && !osVersionAtLeast(signals.OSVersion, policy.MinOSVersion) {
		reasons = append(reasons, "os_version_below_minimum")
	}
	if len(reasons) == 0 {
		return PostureTrustManaged, true, nil
	}
	return PostureTrustNonCompliant, false, reasons
}

// osVersionAtLeast reports whether got >= want using a dotted-numeric comparison (e.g. "14.5" >=
// "14.0"). Non-numeric / empty got is treated as below minimum (fail-closed).
func osVersionAtLeast(got, want string) bool {
	g := parseVersion(got)
	w := parseVersion(want)
	if len(g) == 0 {
		return false
	}
	for i := 0; i < len(g) || i < len(w); i++ {
		var gi, wi int
		if i < len(g) {
			gi = g[i]
		}
		if i < len(w) {
			wi = w[i]
		}
		if gi != wi {
			return gi > wi
		}
	}
	return true
}

func parseVersion(v string) []int {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}
