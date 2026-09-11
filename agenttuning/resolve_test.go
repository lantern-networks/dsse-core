package agenttuning

import "testing"

func TestResolve_MostSpecificWins(t *testing.T) {
	scoped := []ScopedTuning{
		{ScopeType: ScopeTenant, Captive: &CaptiveTuning{TimeoutSec: 200, ProbeIntervalSec: 3}},
		{ScopeType: ScopeDeviceGroup, ScopeID: "dev", Captive: &CaptiveTuning{TimeoutSec: 300}},    // group overrides tenant timeout
		{ScopeType: ScopeDevice, ScopeID: "win-1", Captive: &CaptiveTuning{ProbeIntervalSec: 5}},   // device overrides probe
		{ScopeType: ScopeDeviceGroup, ScopeID: "finance", Captive: &CaptiveTuning{TimeoutSec: 90}}, // other group — must not apply
	}
	got := Resolve("acme", "dev", "win-1", scoped)
	if got.TenantID != "acme" || got.DeviceGroup != "dev" || got.Kind != TuningKind {
		t.Fatalf("scope metadata wrong: %+v", got)
	}
	if got.Captive == nil || got.Captive.TimeoutSec != 300 {
		t.Fatalf("group must override tenant timeout: %+v", got.Captive)
	}
	if got.Captive.ProbeIntervalSec != 5 {
		t.Fatalf("device must override probe: %+v", got.Captive)
	}
}

func TestResolve_DeviceNotInGroup_GetsOnlyTenant(t *testing.T) {
	scoped := []ScopedTuning{
		{ScopeType: ScopeTenant, Captive: &CaptiveTuning{TimeoutSec: 200}},
		{ScopeType: ScopeDeviceGroup, ScopeID: "dev", Captive: &CaptiveTuning{TimeoutSec: 300}},
	}
	// device is in group "finance" (no policy) → only the tenant timeout applies.
	got := Resolve("acme", "finance", "win-2", scoped)
	if got.Captive == nil || got.Captive.TimeoutSec != 200 {
		t.Fatalf("device outside the dev group must get tenant tuning only: %+v", got.Captive)
	}
}

func TestResolve_HostsOverride(t *testing.T) {
	scoped := []ScopedTuning{
		{ScopeType: ScopeTenant, Captive: &CaptiveTuning{DetectHosts: []string{"a.com"}}},
		{ScopeType: ScopeDeviceGroup, ScopeID: "dev", Captive: &CaptiveTuning{DetectHosts: []string{"b.com", " "}}},
	}
	got := Resolve("acme", "dev", "win-1", scoped)
	if got.Captive == nil || len(got.Captive.DetectHosts) != 1 || got.Captive.DetectHosts[0] != "b.com" {
		t.Fatalf("group hosts must override + be cleaned: %+v", got.Captive)
	}
}

func TestResolve_NoScopes_EmptyCaptive(t *testing.T) {
	got := Resolve("acme", "dev", "win-1", nil)
	if got.Captive != nil {
		t.Fatalf("no scoped policies => nil captive (agent keeps current): %+v", got.Captive)
	}
	// And the resolved policy is a valid signable envelope shape (kind set).
	if got.Kind != TuningKind {
		t.Fatalf("kind must be set for signing: %q", got.Kind)
	}
}

func TestResolve_EmptyGroup_SkipsGroupScope(t *testing.T) {
	scoped := []ScopedTuning{
		{ScopeType: ScopeTenant, Captive: &CaptiveTuning{TimeoutSec: 200}},
		{ScopeType: ScopeDeviceGroup, ScopeID: "", Captive: &CaptiveTuning{TimeoutSec: 999}}, // empty group id — must not match
	}
	got := Resolve("acme", "", "win-1", scoped)
	if got.Captive == nil || got.Captive.TimeoutSec != 200 {
		t.Fatalf("empty group must not pick up a blank-scoped policy: %+v", got.Captive)
	}
}
