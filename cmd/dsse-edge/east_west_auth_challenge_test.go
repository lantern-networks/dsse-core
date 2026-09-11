package main

import (
	"net/http"
	"testing"
	"time"

	eastwest "github.com/lantern-networks/dsse-core/eastwest"

	"github.com/lantern-networks/dsse-core/model"
)

func TestDecisionRequiresAuthentication(t *testing.T) {
	if !eastwest.RequiresAuthentication("authenticate_required") {
		t.Fatal("authenticate_required must require authentication (hold)")
	}
	for _, d := range []string{"allow", "deny", "require_human_approval", ""} {
		if eastwest.RequiresAuthentication(d) {
			t.Fatalf("%q must not be treated as authenticate hold", d)
		}
	}
}

func TestStatusForDecisionAuthenticateRequiredIs401(t *testing.T) {
	if got := statusForDecision("authenticate_required"); got != http.StatusUnauthorized {
		t.Fatalf("authenticate_required status got %d want 401", got)
	}
	if got := statusForDecision("deny"); got != http.StatusForbidden {
		t.Fatalf("deny status got %d want 403", got)
	}
}

func TestBuildEastWestAuthChallengeBinding(t *testing.T) {
	// subject falls back to user; destination falls back to application; protocol lowercased.
	c := eastwest.BuildAuthChallenge(model.DecisionRequest{
		TenantID:      "t1",
		UserID:        "u1",
		DeviceID:      "dev1",
		ApplicationID: "app-server-b",
		ServiceFamily: "RDP",
	})
	if c.TenantID != "t1" || c.SubjectUserID != "u1" || c.DeviceID != "dev1" {
		t.Fatalf("binding mismatch: %+v", c)
	}
	if c.Destination != "app-server-b" {
		t.Fatalf("destination should fall back to application id; got %q", c.Destination)
	}
	if c.Protocol != "rdp" {
		t.Fatalf("protocol should be lowercased; got %q", c.Protocol)
	}

	// explicit subject + destination win over fallbacks.
	c2 := eastwest.BuildAuthChallenge(model.DecisionRequest{
		TenantID: "t1", UserID: "u1", SubjectUserID: "sub1", Destination: "server-b", ServiceFamily: "ssh",
	})
	if c2.SubjectUserID != "sub1" || c2.Destination != "server-b" {
		t.Fatalf("explicit subject/destination should win; got %+v", c2)
	}
}

func TestEastWestAuthChallengeStoreCreateListExpire(t *testing.T) {
	store := eastwest.NewAuthChallengeStore()
	now := time.Now()

	created := store.Create(eastwest.BuildAuthChallenge(model.DecisionRequest{
		TenantID: "t1", UserID: "u1", DeviceID: "dev1", Destination: "server-b", ServiceFamily: "ssh",
	}), now)
	if created.ID == "" || created.Status != "pending" {
		t.Fatalf("Create must assign id + pending status; got %+v", created)
	}
	if _, ok := store.Get(created.ID); !ok {
		t.Fatal("created challenge must be retrievable")
	}

	// Pending + same tenant -> listed.
	if got := store.ListPending("t1", now); len(got) != 1 || got[0].ID != created.ID {
		t.Fatalf("expected 1 pending challenge for t1; got %v", got)
	}
	// Different tenant -> not listed.
	if got := store.ListPending("other", now); len(got) != 0 {
		t.Fatalf("other tenant must see no challenges; got %v", got)
	}
	// After the TTL -> excluded from pending.
	if got := store.ListPending("t1", now.Add(eastwest.AuthChallengeTTL+time.Minute)); len(got) != 0 {
		t.Fatalf("expired challenge must not be listed; got %v", got)
	}
}
