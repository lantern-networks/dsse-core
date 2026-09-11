package main

import (
	"testing"
	"time"
)

func b(v bool) *bool { return &v }

// ★ The defect this closes, measured on the reference Edge 2026-08-10: mac-dev-1 was enrolled, alive and
// reporting every 15 seconds, and had NO entry in this store at all — because the only path that wrote one was
// the steer-mux CONNECT, so presence and posture were side effects of CARRYING TRAFFIC. The Console therefore
// said the macOS NE reported neither disk encryption nor firewall. Nothing was wrong with the collector.
func TestAReportingDeviceIsPresentEvenIfItIsNotSteering(t *testing.T) {
	s := newEndpointRuntimeStore()
	now := time.Now()

	s.ingestFromReport("mac-dev-1", "tenant_lab", "macOS 26.0.0", b(true), b(true), "macos_collector", "203.0.113.7", now)

	snap := s.snapshot(now)
	e, ok := snap["mac-dev-1"]
	if !ok {
		t.Fatal("a device that reports every 15 seconds is absent from the fleet view unless it happens to be carrying traffic")
	}
	if e.Posture.DiskEncryptionEnabled == nil || !*e.Posture.DiskEncryptionEnabled {
		t.Fatalf("disk encryption did not survive the report: %+v", e.Posture)
	}
	if e.Posture.FirewallEnabled == nil || !*e.Posture.FirewallEnabled {
		t.Fatalf("firewall did not survive the report: %+v", e.Posture)
	}
	if e.OS != "macOS 26.0.0" {
		t.Fatalf("OS = %q", e.OS)
	}
}

// ★ Absent is not "off". An agent that cannot read a signal reports nothing for it, and reading that as
// disabled turns "we cannot see this machine" into "this machine is non-compliant" — opposite responses.
func TestAnUnreportedSignalIsNotRecordedAsDisabled(t *testing.T) {
	s := newEndpointRuntimeStore()
	now := time.Now()

	s.ingestFromReport("mac-dev-1", "tenant_lab", "macOS 26.0.0", nil, nil, "macos_collector", "203.0.113.7", now)

	e := s.snapshot(now)["mac-dev-1"]
	if e.Posture.DiskEncryptionEnabled != nil || e.Posture.FirewallEnabled != nil {
		t.Fatalf("an unreported signal was recorded as a value: %+v", e.Posture)
	}
}

// One readable signal must not erase the other. A collector that can read the firewall and not FileVault
// would otherwise blank a previously-reported encryption state every 15 seconds.
func TestOneSignalDoesNotEraseTheOther(t *testing.T) {
	s := newEndpointRuntimeStore()
	now := time.Now()

	s.ingestFromReport("mac-dev-1", "t", "macOS 26.0.0", b(true), b(true), "macos_collector", "203.0.113.7", now)
	s.ingestFromReport("mac-dev-1", "t", "macOS 26.0.0", nil, b(false), "macos_collector", "203.0.113.7", now.Add(15*time.Second))

	e := s.snapshot(now.Add(15 * time.Second))["mac-dev-1"]
	if e.Posture.DiskEncryptionEnabled == nil || !*e.Posture.DiskEncryptionEnabled {
		t.Fatalf("the previously reported encryption state was erased by a report that omitted it: %+v", e.Posture)
	}
	if e.Posture.FirewallEnabled == nil || *e.Posture.FirewallEnabled {
		t.Fatalf("the firewall update did not land: %+v", e.Posture)
	}
}

// An empty identity writes nothing: the store is keyed by the cert-proven identity and an unkeyed entry would
// be a device nobody can act on.
func TestAReportWithNoIdentityIsIgnored(t *testing.T) {
	s := newEndpointRuntimeStore()
	s.ingestFromReport("  ", "t", "macOS", b(true), b(true), "macos_collector", "203.0.113.7", time.Now())
	if len(s.snapshot(time.Now())) != 0 {
		t.Fatal("an unidentified report created an entry")
	}
}
