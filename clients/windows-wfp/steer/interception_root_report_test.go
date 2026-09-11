package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// The adopted bundle's interception roots persist so the report has a stable "wanted" list between bundle
// changes (a non-rotating deployment never publishes a new one).
func TestAdvertisedInterceptionRootsPersist(t *testing.T) {
	dir := t.TempDir()
	raw, _ := json.Marshal(adoptedTrustPointer{
		Serial: 1, AdoptedAt: "2026-08-01T00:00:00Z",
		InterceptionRootSHA256: []string{"5a74ac31d78c094383d49e30608bf72f56bba6846f3fd9d92b98a7b120b8f439"},
	})
	if err := os.WriteFile(filepath.Join(dir, adoptedPointerFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	got := advertisedInterceptionRoots(dir)
	if len(got) != 1 || got[0] != "5a74ac31d78c094383d49e30608bf72f56bba6846f3fd9d92b98a7b120b8f439" {
		t.Fatalf("advertised interception roots = %v", got)
	}
	// No pointer => nothing wanted.
	if advertisedInterceptionRoots(t.TempDir()) != nil {
		t.Fatal("a device with no adopted bundle must advertise no interception roots")
	}
}

// The report carries the found roots, and OMITS the field when none are found — the Edge reads absent as
// "unknown", never as "trusts none", so an unanswered device must not appear on the wire as an empty answer.
func TestExclusionSyncReportsInterceptionRootsPresentOnly(t *testing.T) {
	signer, _ := agentpolicy.LoadOrGenerateSigner("", true)
	var reportFails atomic.Bool
	var cap capturedReport
	srv := reportingPolicyServer(t, signer, nil, &reportFails, &cap)
	defer srv.Close()

	// Found: report the fingerprints.
	s := &exclusionSync{
		client: srv.Client(), baseURL: srv.URL, pinHex: "", localBaseline: []string{"example-app"},
		apply:             func([]string) {},
		interceptionRoots: func() []string { return []string{"aa", "bb"} },
	}
	if _, err := s.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body, _ := cap.body.Load().(map[string]any)
	roots, ok := body["pinned_interception_root_sha256"].([]any)
	if !ok || len(roots) != 2 {
		t.Fatalf("pinned_interception_root_sha256 = %v, want 2", body["pinned_interception_root_sha256"])
	}

	// Found none: the field must be ABSENT (omitempty), not an empty array.
	var cap2 capturedReport
	srv2 := reportingPolicyServer(t, signer, nil, &reportFails, &cap2)
	defer srv2.Close()
	s2 := &exclusionSync{
		client: srv2.Client(), baseURL: srv2.URL, pinHex: "", localBaseline: []string{"example-app"},
		apply:             func([]string) {},
		interceptionRoots: func() []string { return nil },
	}
	if _, err := s2.refreshOnce(context.Background()); err != nil {
		t.Fatalf("refreshOnce: %v", err)
	}
	body2, _ := cap2.body.Load().(map[string]any)
	if _, present := body2["pinned_interception_root_sha256"]; present {
		t.Fatalf("found none must OMIT the field (unknown != trusts-none), got %v", body2["pinned_interception_root_sha256"])
	}
}
