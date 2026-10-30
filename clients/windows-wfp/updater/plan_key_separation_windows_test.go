//go:build windows

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildRejectsExplicitPlanPinIfAllKeysCollide(t *testing.T) {
	key := strings.Repeat("a", 64)
	_, err := build(buildOpts{
		planFile:   filepath.Join(t.TempDir(), "missing-local-plan.json"),
		updatePins: key, planPin: strings.ToUpper(key),
	})
	if err == nil || !strings.Contains(err.Error(), "plan-signing") {
		t.Fatalf("configured plan pin must not become an unverified rollout: %v", err)
	}
}

func TestBuildRetainsDistinctPlanPinAfterPartialCollision(t *testing.T) {
	update, plan := strings.Repeat("a", 64), strings.Repeat("b", 64)
	u, err := build(buildOpts{
		planFile:   filepath.Join(t.TempDir(), "missing-local-plan.json"),
		updatePins: update, planPin: update + "," + plan,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(u.planPins) != 1 || u.planPins[0] != plan {
		t.Fatalf("usable plan authority lost: %v", u.planPins)
	}
}

func TestBuildKeepsLegacyUnconfiguredPlanOptOut(t *testing.T) {
	u, err := build(buildOpts{
		planFile:   filepath.Join(t.TempDir(), "missing-local-plan.json"),
		updatePins: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(u.planPins) != 0 {
		t.Fatalf("unexpected plan key: %v", u.planPins)
	}
}
