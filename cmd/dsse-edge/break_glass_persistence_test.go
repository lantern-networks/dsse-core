package main

import (
	"path/filepath"
	"testing"
	"time"
)

// TestBreakGlassPersistenceRoundTrip proves a break-glass request survives a restart through the requested ->
// approved -> session_issued lifecycle: a second store pointed at the same path rehydrates the durable state.
func TestBreakGlassPersistenceRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "break_glass.json")

	s1 := newBreakGlassRequestStore()
	if err := s1.SetStatePath(path); err != nil {
		t.Fatalf("set state path: %v", err)
	}
	req, err := s1.Create(breakGlassSessionRequest{TenantID: "acme", UserID: "ops1", Reason: "incident-42"}, "acme", now)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s1.Approve(req.ID, breakGlassApprovalRequest{ApproverUserID: "mgr1", Reason: "ack"}, now); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Fresh store, same path: the approved request is rehydrated and the lifecycle can continue.
	s2 := newBreakGlassRequestStore()
	if err := s2.SetStatePath(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := s2.Get(req.ID)
	if !ok {
		t.Fatal("request should be present after restart")
	}
	if got.Status != "approved" {
		t.Fatalf("status should be approved after restart, got %q", got.Status)
	}
	// The rehydrated approved request can still transition to session_issued.
	if _, err := s2.MarkSessionIssued(req.ID, "sess_bg_test", now); err != nil {
		t.Fatalf("mark session issued after restart: %v", err)
	}
}
