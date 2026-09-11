//go:build windows

package main

import (
	"testing"
	"time"
)

// agentVersion must report the BUILD, and must be honest when it does not know it.
//
// The agent reported the literal "wfp-steer" until 2026-08-05 — a steering-backend name, identical on every
// machine — so a fleet's version distribution was one meaningless bucket. The failure to avoid now is the
// opposite one: a binary that was never stamped must not report a plausible-looking version it does not have.
func TestAgentVersionReportsTheBuild(t *testing.T) {
	saved := [4]string{buildVersion, buildCommit, buildDate, buildDirty}
	defer func() { buildVersion, buildCommit, buildDate, buildDirty = saved[0], saved[1], saved[2], saved[3] }()

	cases := []struct {
		name                   string
		version, commit, dirty string
		want                   string
	}{
		{"stamped", "0.1.0", "abc1234", "false", "0.1.0+abc1234"},
		{"a dirty tree is marked — it matches no commit", "0.1.0", "abc1234", "true", "0.1.0+abc1234.dirty"},
		{"unstamped says so rather than inventing a number", "0.0.0-dev", "unknown", "unknown", "0.0.0-dev"},
		{"empty version falls back to the dev marker", "", "unknown", "unknown", "0.0.0-dev"},
	}
	for _, tc := range cases {
		buildVersion, buildCommit, buildDirty = tc.version, tc.commit, tc.dirty
		if got := agentVersion(); got != tc.want {
			t.Fatalf("%s: agentVersion() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The heartbeat and the registration must carry the SAME version. They were two separate hardcoded literals,
// which is how they could ever disagree.
func TestHeartbeatAndRegisterReportTheSameVersion(t *testing.T) {
	saved := [2]string{buildVersion, buildCommit}
	defer func() { buildVersion, buildCommit = saved[0], saved[1] }()
	buildVersion, buildCommit = "0.1.0", "abc1234"

	cfg := heartbeatConfig{deviceID: "win-dev-1", tenantID: "tenant_lab_001"}
	reg := deviceRegisterBody(cfg)["agent_version"]
	beat := deviceHeartbeatBody(cfg, time.Date(2026, 8, 5, 11, 0, 0, 0, time.UTC), true)["agent_version"]
	if reg != beat {
		t.Fatalf("register reports %v but heartbeat reports %v", reg, beat)
	}
	if reg != "0.1.0+abc1234" {
		t.Fatalf("agent_version = %v, want the stamped build", reg)
	}
}

// The heartbeat must carry every posture axis the agent can read.
//
// It carried only enforcement_agent_healthy, so the Edge — which re-derives trust from whatever a heartbeat
// contains — saw disk encryption and firewall as unknown and failed both. win-dev-1 was permanently
// noncompliant while BitLocker and the firewall were on, and the agent had those readings all along: it
// collects them for the steer-mux CONNECT headers and just never put them in the beat.
//
// The body builder is pure apart from the two registry/COM reads, which return "" off a real Windows box, so
// this asserts the SHAPE and the fail-safe rule: an unreadable signal is OMITTED, never guessed.
func TestHeartbeatPostureCarriesReadableAxesAndOmitsUnreadableOnes(t *testing.T) {
	cfg := heartbeatConfig{deviceID: "win-dev-1", tenantID: "tenant_lab_001"}
	body := deviceHeartbeatBody(cfg, time.Date(2026, 8, 5, 11, 0, 0, 0, time.UTC), true)

	posture, ok := body["posture"].(map[string]any)
	if !ok {
		t.Fatalf("posture is %T, want a map", body["posture"])
	}
	if posture["enforcement_agent_healthy"] != true {
		t.Fatalf("enforcement_agent_healthy = %v, want true — the W-3 tamper signal must survive", posture["enforcement_agent_healthy"])
	}
	if posture["source"] != "windows_collector" {
		t.Fatalf("source = %v, want windows_collector (the Edge's normalizer keys on it)", posture["source"])
	}
	// Screen lock was REMOVED as a posture axis on 2026-08-05 — nothing measured it, and requiring it failed
	// the fleet on absence. Reintroducing the field here would resurrect an axis the Edge no longer has.
	if _, present := posture["screen_lock_enabled"]; present {
		t.Fatalf("screen_lock_enabled is present; the axis was removed and must not come back through the agent")
	}
	// Whatever the reads returned, a present value must be a bool — never the raw "on"/"off" status string,
	// which the Edge would decode as unknown.
	for _, axis := range []string{"disk_encryption_enabled", "firewall_enabled"} {
		if v, present := posture[axis]; present {
			if _, isBool := v.(bool); !isBool {
				t.Fatalf("%s = %v (%T), want a bool", axis, v, v)
			}
		}
	}
}
