package main

import (
	"path/filepath"
	"testing"
	"time"
)

// The cutoff must outlive the process. A restart that forgot it would stop a fleet-wide renewal half-way
// through — silently, and precisely for the devices that had not checked in yet, which are the ones the
// declaration was supposed to reach.
func TestRenewBeforeCutoffSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "renew_before.json")
	at := time.Date(2026, 7, 31, 4, 0, 0, 0, time.UTC)

	if err := newRenewBeforeSetting(path).Set(at); err != nil {
		t.Fatalf("set: %v", err)
	}

	restarted := newRenewBeforeSetting(path)
	got, ok := restarted.At()
	if !ok {
		t.Fatal("the cutoff did not survive — every device that had not yet checked in would never be told")
	}
	if !got.Equal(at) {
		t.Fatalf("cutoff = %v, want %v", got, at)
	}
	if restarted.RFC3339() != at.Format(time.RFC3339) {
		t.Fatalf("RFC3339 = %q, want %q", restarted.RFC3339(), at.Format(time.RFC3339))
	}
}

// Nothing being asked is the ordinary state, and it must be expressible. An agent that never sees the field
// behaves exactly as it did before, so an empty rendering is what keeps the field out of the signed policy.
func TestRenewBeforeIsAbsentUntilAskedAndAfterClearing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "renew_before.json")
	s := newRenewBeforeSetting(path)
	if s.RFC3339() != "" {
		t.Fatalf("a fresh setting must ask for nothing, got %q", s.RFC3339())
	}

	if err := s.Set(time.Now().UTC()); err != nil {
		t.Fatalf("set: %v", err)
	}
	if s.RFC3339() == "" {
		t.Fatal("after asking, the cutoff must be rendered into the policy")
	}

	if err := s.Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if s.RFC3339() != "" {
		t.Fatal("after clearing, nothing is being asked")
	}
	// Clearing must also survive a restart, or the request would come back from the dead and renew the fleet a
	// second time.
	if reloaded := newRenewBeforeSetting(path); reloaded.RFC3339() != "" {
		t.Fatalf("a cleared request returned after restart: %q", reloaded.RFC3339())
	}
}
