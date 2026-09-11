package device

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func boolp(b bool) *bool { return &b }

func TestPostureEnforcementAgentHealth_W3(t *testing.T) {
	// W-3 enforcement is opt-in: with it required, a healthy agent passes, an unhealthy/missing one fails.
	pol := DefaultPosturePolicy()
	pol.RequireEnforcementAgentHealthy = true
	base := func(agent *bool) *model.DevicePostureSignals {
		return &model.DevicePostureSignals{
			DiskEncryptionEnabled: boolp(true), FirewallEnabled: boolp(true),
			EnforcementAgentHealthy: agent,
		}
	}

	if lvl, ok, _ := DerivePostureTrustLevel(base(boolp(true)), pol); lvl != PostureTrustManaged || !ok {
		t.Fatalf("healthy agent + all signals should be managed, got %q ok=%v", lvl, ok)
	}
	// Tampered agent (false) -> noncompliant with the W-3 reason.
	lvl, ok, reasons := DerivePostureTrustLevel(base(boolp(false)), pol)
	if lvl != PostureTrustNonCompliant || ok || len(reasons) != 1 || reasons[0] != "enforcement_agent_unhealthy_or_unknown" {
		t.Fatalf("tampered agent should be noncompliant(enforcement_agent_unhealthy_or_unknown), got lvl=%q reasons=%v", lvl, reasons)
	}
	// Missing signal (nil) -> fail-closed (non-compliant) when required.
	if lvl, ok, _ := DerivePostureTrustLevel(base(nil), pol); lvl != PostureTrustNonCompliant || ok {
		t.Fatalf("missing agent-health signal must fail-closed when required, got %q ok=%v", lvl, ok)
	}

	// Backward-compat: the DEFAULT policy does NOT require agent-health, so a device that never reports it
	// stays managed (existing devices are not flipped to non-compliant).
	if lvl, ok, _ := DerivePostureTrustLevel(base(nil), DefaultPosturePolicy()); lvl != PostureTrustManaged || !ok {
		t.Fatalf("default policy must not require agent-health (no regression for non-reporting devices), got %q ok=%v", lvl, ok)
	}

	// Tamper regression: healthy(managed) -> tampered(noncompliant) trips PostureRegressed (-> grant revoke).
	prev, _, _ := DerivePostureTrustLevel(base(boolp(true)), pol)
	cur, _, _ := DerivePostureTrustLevel(base(boolp(false)), pol)
	if !PostureRegressed(prev, cur) {
		t.Fatalf("agent tamper must be a posture regression: %q -> %q", prev, cur)
	}
}

func TestDerivePostureTrustLevel(t *testing.T) {
	pol := DefaultPosturePolicy()

	// All required signals satisfied -> managed.
	lvl, ok, reasons := DerivePostureTrustLevel(&model.DevicePostureSignals{
		DiskEncryptionEnabled: boolp(true), FirewallEnabled: boolp(true),
	}, pol)
	if lvl != PostureTrustManaged || !ok || len(reasons) != 0 {
		t.Fatalf("fully compliant should be managed: lvl=%q ok=%v reasons=%v", lvl, ok, reasons)
	}

	// Disk encryption off -> noncompliant with a reason.
	lvl, ok, reasons = DerivePostureTrustLevel(&model.DevicePostureSignals{
		DiskEncryptionEnabled: boolp(false), FirewallEnabled: boolp(true),
	}, pol)
	if lvl != PostureTrustNonCompliant || ok || len(reasons) != 1 || reasons[0] != "disk_encryption_disabled_or_unknown" {
		t.Fatalf("disk off should be noncompliant: lvl=%q ok=%v reasons=%v", lvl, ok, reasons)
	}

	// Missing (nil) signal is treated as non-compliant (unknown != ok).
	if _, ok, _ := DerivePostureTrustLevel(&model.DevicePostureSignals{FirewallEnabled: boolp(true)}, pol); ok {
		t.Fatalf("nil disk encryption signal must be non-compliant")
	}

	// nil signals -> noncompliant.
	if lvl, ok, _ := DerivePostureTrustLevel(nil, pol); lvl != PostureTrustNonCompliant || ok {
		t.Fatalf("nil signals must be noncompliant")
	}

	// OS version floor.
	osPol := PosturePolicy{MinOSVersion: "14.0"}
	if _, ok, _ := DerivePostureTrustLevel(&model.DevicePostureSignals{OSVersion: "14.5"}, osPol); !ok {
		t.Fatalf("14.5 >= 14.0 should pass")
	}
	if _, ok, _ := DerivePostureTrustLevel(&model.DevicePostureSignals{OSVersion: "13.6"}, osPol); ok {
		t.Fatalf("13.6 < 14.0 should fail")
	}
}

// TestHeartbeatEdgeDerivesTrustFromSignals is the anti-spoofing core: when a heartbeat carries
// posture signals, the Edge IGNORES a client-declared trust string and derives the trust itself.
func TestHeartbeatEdgeDerivesTrustFromSignals(t *testing.T) {
	s := NewStore()
	pb := model.PolicyBundle{TenantID: "t"}
	now := time.Now()
	if _, err := s.Register(model.Device{ID: "dev1", TenantID: "t"}, pb, now); err != nil {
		t.Fatal(err)
	}

	// Compromised client claims "managed" but reports disk encryption OFF -> Edge derives noncompliant.
	dev, err := s.Heartbeat(model.DeviceHeartbeat{
		ID:               "dev1",
		DeviceTrustLevel: "managed", // self-declared (must be ignored)
		Posture:          &model.DevicePostureSignals{DiskEncryptionEnabled: boolp(false), FirewallEnabled: boolp(true)},
	}, pb, now)
	if err != nil {
		t.Fatal(err)
	}
	if dev.DeviceTrustLevel != PostureTrustNonCompliant {
		t.Fatalf("Edge must derive noncompliant from signals, not trust the declared 'managed': got %q", dev.DeviceTrustLevel)
	}
	if dev.Metadata["posture_compliant"] != false {
		t.Fatalf("posture_compliant should be false")
	}

	// Honest fully-compliant device -> managed.
	dev, err = s.Heartbeat(model.DeviceHeartbeat{
		ID:      "dev1",
		Posture: &model.DevicePostureSignals{DiskEncryptionEnabled: boolp(true), FirewallEnabled: boolp(true)},
	}, pb, now)
	if err != nil {
		t.Fatal(err)
	}
	if dev.DeviceTrustLevel != PostureTrustManaged {
		t.Fatalf("fully compliant device should be managed: got %q", dev.DeviceTrustLevel)
	}

	// No signals -> the claim is IGNORED and the last posture-derived trust stands (review #18): the old
	// "back-compat" fallback let a compromised endpoint simply omit posture and claim any level.
	dev, err = s.Heartbeat(model.DeviceHeartbeat{ID: "dev1", DeviceTrustLevel: "byod"}, pb, now)
	if err != nil {
		t.Fatal(err)
	}
	if dev.DeviceTrustLevel != PostureTrustManaged {
		t.Fatalf("a signal-less heartbeat must not change the posture-derived trust: got %q", dev.DeviceTrustLevel)
	}
}

// Review #18: registration is the other self-assertion door — a body-declared DeviceTrustLevel must not
// stick. With posture signals the level is derived; without them the device starts "unknown".
func TestRegisterDerivesTrustIgnoringClaim(t *testing.T) {
	s := NewStore()
	pb := model.PolicyBundle{TenantID: "t"}
	now := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)

	claimed, err := s.Register(model.Device{ID: "dev-claim", TenantID: "t", DeviceTrustLevel: "managed"}, pb, now)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.DeviceTrustLevel != "unknown" {
		t.Fatalf("posture-less registration must start unknown regardless of the claim: got %q", claimed.DeviceTrustLevel)
	}

	withPosture, err := s.Register(model.Device{
		ID: "dev-posture", TenantID: "t", DeviceTrustLevel: "managed", // claim still ignored; signals decide
		Posture: &model.DevicePostureSignals{DiskEncryptionEnabled: boolp(false), FirewallEnabled: boolp(true)},
	}, pb, now)
	if err != nil {
		t.Fatal(err)
	}
	if withPosture.DeviceTrustLevel != PostureTrustNonCompliant {
		t.Fatalf("registration with signals must derive the trust: got %q", withPosture.DeviceTrustLevel)
	}
}
