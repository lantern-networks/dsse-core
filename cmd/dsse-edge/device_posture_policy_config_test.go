package main

import (
	"testing"
)

func TestPosturePolicyFromEnvDefaultsAndOverrides(t *testing.T) {
	t.Setenv("DSSE_POSTURE_REQUIRE_DISK_ENCRYPTION", "")
	t.Setenv("DSSE_POSTURE_REQUIRE_FIREWALL", "")
	t.Setenv("DSSE_POSTURE_MIN_OS_VERSION", "")
	p := posturePolicyFromEnv()
	// Screen lock was removed as an axis on 2026-08-05: nothing measured it, so requiring it failed every
	// device on absence rather than on a violation. The defaults are now the axes an agent can actually read.
	if !p.RequireDiskEncryption || !p.RequireFirewall || p.MinOSVersion != "" {
		t.Fatalf("defaults should require disk + firewall and set no OS floor: %+v", p)
	}
	t.Setenv("DSSE_POSTURE_MIN_OS_VERSION", "14.0")
	p = posturePolicyFromEnv()
	if !p.RequireDiskEncryption || !p.RequireFirewall {
		t.Fatalf("disk/firewall should stay required")
	}
	if p.MinOSVersion != "14.0" {
		t.Fatalf("min os version should be 14.0, got %q", p.MinOSVersion)
	}
}
