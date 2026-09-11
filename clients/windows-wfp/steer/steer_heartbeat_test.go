//go:build windows

package main

import (
	"testing"
	"time"
)

func TestDeviceHeartbeatBodyShape(t *testing.T) {
	cfg := heartbeatConfig{deviceID: "win-dev-1", tenantID: "tenant_lab"}
	now := time.Date(2026, 6, 18, 1, 2, 3, 0, time.UTC)
	b := deviceHeartbeatBody(cfg, now, true)
	if b["id"] != "win-dev-1" || b["tenant_id"] != "tenant_lab" || b["status"] != "active" {
		t.Fatalf("heartbeat body wrong: %#v", b)
	}
	if b["timestamp"] != "2026-06-18T01:02:03Z" {
		t.Fatalf("timestamp = %v, want RFC3339 UTC 2026-06-18T01:02:03Z", b["timestamp"])
	}
	// W-3: posture carries the enforcement-agent-healthy signal.
	p, ok := b["posture"].(map[string]any)
	if !ok || p["enforcement_agent_healthy"] != true {
		t.Fatalf("posture.enforcement_agent_healthy not reported true: %#v", b["posture"])
	}
	if deviceHeartbeatBody(cfg, now, false)["posture"].(map[string]any)["enforcement_agent_healthy"] != false {
		t.Fatal("unhealthy not propagated to posture")
	}
	r := deviceRegisterBody(cfg)
	if r["id"] != "win-dev-1" || r["device_trust_level"] != "managed" {
		t.Fatalf("register body wrong: %#v", r)
	}
}

func TestHeartbeatBaseURL(t *testing.T) {
	cfg := heartbeatConfig{transport: transportConfig{host: "203.0.113.10:18543"}}
	if got := cfg.baseURL(); got != "https://203.0.113.10:18543" {
		t.Fatalf("baseURL = %q", got)
	}
}

func TestRunHeartbeatRequiresTransportAndID(t *testing.T) {
	// no transport => error
	if err := runHeartbeat(heartbeatConfig{deviceID: "win-dev-1"}); err == nil {
		t.Fatal("expected error without (T) transport + client cert")
	}
}

// ★ The tenant the RECORD carries and the tenant SELF-REGISTRATION would write are different questions, and
// the MSI is why. Its service line is `--service-run --config-store` and nothing else, so --device-tenant is
// empty on every device the product installs; recording that empty value leaves the plan-addressing check
// running device-only on the whole fleet while looking complete. The verified profile's tenant is a CP-signed
// statement about this device and is the better answer for the record — and only for the record.
func TestTheRecordedTenantFallsBackToTheVerifiedProfile(t *testing.T) {
	if got := recordedTenant(heartbeatConfig{profileTenantID: "tenant_lab"}); got != "tenant_lab" {
		t.Errorf("an MSI box with no --device-tenant recorded %q — the plan-addressing check then compares "+
			"nothing on every device the product installs", got)
	}
	// An operator who typed one still wins: --device-tenant is what a person asserted about this box.
	if got := recordedTenant(heartbeatConfig{tenantID: "typed", profileTenantID: "profile"}); got != "typed" {
		t.Errorf("recordedTenant = %q, want the operator's --device-tenant", got)
	}
	if got := recordedTenant(heartbeatConfig{tenantID: "  ", profileTenantID: "profile"}); got != "profile" {
		t.Errorf("whitespace is not an answer, got %q", got)
	}
	if got := recordedTenant(heartbeatConfig{}); got != "" {
		t.Errorf("with neither source the record must stay empty (unknown, not a match): got %q", got)
	}
}
