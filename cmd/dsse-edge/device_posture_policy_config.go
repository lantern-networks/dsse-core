package main

import (
	"log"
	"os"
	"strings"

	devicestore "github.com/lantern-networks/dsse-core/device"
)

// posturePolicyFromEnv builds the Edge-side device posture ruleset from env (B-2). Admins
// configure which real signals a "managed" device must satisfy. Defaults to the safe baseline
// (disk encryption + firewall + screen lock required). Env (DSSE_POSTURE_* convention):
//
//	DSSE_POSTURE_REQUIRE_DISK_ENCRYPTION = true|false   (default true)
//	DSSE_POSTURE_REQUIRE_FIREWALL        = true|false   (default true)
//	DSSE_POSTURE_REQUIRE_AGENT_HEALTHY   = true|false   (default false; W-3 tamper-evident, opt-in)
//	DSSE_POSTURE_MIN_OS_VERSION          = "14.0"       (default "" = no floor)
func posturePolicyFromEnv() devicestore.PosturePolicy {
	policy := devicestore.DefaultPosturePolicy()
	policy.RequireDiskEncryption = envBoolDefault("DSSE_POSTURE_REQUIRE_DISK_ENCRYPTION", policy.RequireDiskEncryption)
	policy.RequireFirewall = envBoolDefault("DSSE_POSTURE_REQUIRE_FIREWALL", policy.RequireFirewall)
	// W-3 (tamper-evident): opt-in so non-reporting devices are not flipped to non-compliant by default.
	policy.RequireEnforcementAgentHealthy = envBoolDefault("DSSE_POSTURE_REQUIRE_AGENT_HEALTHY", policy.RequireEnforcementAgentHealthy)
	if v := strings.TrimSpace(os.Getenv("DSSE_POSTURE_MIN_OS_VERSION")); v != "" {
		policy.MinOSVersion = v
	}
	return policy
}

func envBoolDefault(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// posturePolicyConfigurableStore is implemented by the in-memory device store; lets the edge apply
// the configured posture ruleset at boot.
type posturePolicyConfigurableStore interface {
	SetPosturePolicy(devicestore.PosturePolicy) error
}

// applyConfiguredPosturePolicy sets the env-derived posture ruleset on the device store if it
// supports configuration (no-op otherwise, e.g. a postgres-backed store).
func applyConfiguredPosturePolicy(store any) {
	if setter, ok := store.(posturePolicyConfigurableStore); ok {
		if err := setter.SetPosturePolicy(posturePolicyFromEnv()); err != nil {
			// Applied in memory; not durable. Said out loud rather than returned: this runs at startup, and an
			// Edge that refuses to boot over a posture snapshot is a worse outcome than one that boots and says
			// the policy will not survive a restart.
			log.Printf("★ device posture policy applied but NOT stored durably (%v) — it will revert to the "+
				"default on the next restart", err)
		}
	}
}
