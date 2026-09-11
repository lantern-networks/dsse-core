package eastwest

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestRequiresAuthentication(t *testing.T) {
	if !RequiresAuthentication("authenticate_required") {
		t.Fatal("authenticate_required must require authentication")
	}
	if RequiresAuthentication("allow") {
		t.Fatal("allow must not require authentication")
	}
}

func TestAuthChallengeLifecycle(t *testing.T) {
	store := NewAuthChallengeStore()
	now := time.Now().UTC()
	ch := BuildAuthChallenge(model.DecisionRequest{TenantID: "t1", UserID: "u1", Destination: "10.0.0.5", ServiceFamily: "ssh"})

	created := store.Create(ch, now)
	if created.ID == "" {
		t.Fatal("Create must mint an id")
	}
	if created.Status != "pending" {
		t.Fatalf("new challenge status = %q, want pending", created.Status)
	}
	if created.SubjectUserID != "u1" {
		t.Fatalf("subject = %q, want u1 (from UserID)", created.SubjectUserID)
	}

	got, ok := store.Get(created.ID)
	if !ok || got.ID != created.ID {
		t.Fatalf("Get(%s) = (%+v, %v), want the created challenge", created.ID, got, ok)
	}
	if pending := store.ListPending("t1", now); len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}

	completed, ok := store.Complete(created.ID, now)
	if !ok || completed.Status != "completed" {
		t.Fatalf("Complete = (%+v, %v), want a completed challenge", completed, ok)
	}
	// A completed challenge is no longer pending.
	if pending := store.ListPending("t1", now); len(pending) != 0 {
		t.Fatalf("pending after complete = %d, want 0", len(pending))
	}
	// Cross-tenant isolation.
	if pending := store.ListPending("t2", now); len(pending) != 0 {
		t.Fatalf("other tenant pending = %d, want 0", len(pending))
	}
}
