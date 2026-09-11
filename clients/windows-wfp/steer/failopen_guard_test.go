package main

import (
	"strings"
	"testing"
	"time"
)

// TestValidateFailOpenPostureRefusesWithoutAck locks in the production guard: --fail-open is refused unless
// --acknowledge-fail-open is explicitly set, so the default (production) is structurally fail-closed; strict
// fail-closed is always allowed.
func TestValidateFailOpenPostureRefusesWithoutAck(t *testing.T) {
	if err := validateFailOpenPosture(true, false); err == nil {
		t.Fatal("--fail-open without --acknowledge-fail-open must be REFUSED (got nil)")
	}
	if err := validateFailOpenPosture(true, true); err != nil {
		t.Fatalf("--fail-open with acknowledgment must be allowed: %v", err)
	}
	if err := validateFailOpenPosture(false, false); err != nil {
		t.Fatalf("strict fail-closed (no fail-open) must be allowed: %v", err)
	}
	if err := validateFailOpenPosture(false, true); err != nil {
		t.Fatalf("acknowledgment without --fail-open must be allowed: %v", err)
	}
}

// TestFailOpenPostureBannerIsLoud ensures the enabled-posture banner names the risk clearly (so it can never be
// a silent line in the logs).
func TestFailOpenPostureBannerIsLoud(t *testing.T) {
	b := failOpenPostureBanner(20 * time.Second)
	for _, want := range []string{"FAIL-OPEN", "UNMEDIATED", "production", "20s"} {
		if !strings.Contains(b, want) {
			t.Fatalf("banner missing %q: %s", want, b)
		}
	}
}

// ★ The banner must say how to LEAVE, not only what fail-open does (2026-08-31).
//
// Nobody enables a stabilization posture intending to keep it, so the operator's real question is how to get
// back — and the answer is not where they will look. Re-applying the profile that preceded this one is refused
// by the anti-rollback floor (measured on win-dev-1: "KEEPING the profile issued <new>; the offered one was
// issued earlier"), so the way back runs through the control plane. What makes that worth a line in a startup
// banner rather than a runbook is the ORDER: the reason to reach for fail-open is usually that the deployment
// is unreachable, which is the same condition that puts the new profile out of reach.
func TestFailOpenPostureBannerSaysThereIsNoLocalWayBack(t *testing.T) {
	b := failOpenPostureBanner(20 * time.Second)
	// That going back needs a NEW document, not the old one.
	if !strings.Contains(b, "NEW profile") {
		t.Errorf("banner does not say leaving fail-open needs a newly issued profile: %s", b)
	}
	// That the old one is actively refused — otherwise an operator tries it and reads the refusal as a fault.
	if !strings.Contains(b, "anti-rollback floor") {
		t.Errorf("banner does not name what refuses the previous profile, so its refusal will read as a bug: %s", b)
	}
	// ★ and the trap itself: the outage you enabled this for is the outage that hides the way out.
	if !strings.Contains(b, "could not reach") {
		t.Errorf("banner does not warn that the way back is behind the thing that was unreachable: %s", b)
	}
}
