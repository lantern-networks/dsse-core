package session

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestGetActiveAtRejectsExpiredAndMalformedSessions(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	store := NewStore()
	expires := now.Add(time.Minute).Format(time.RFC3339)
	_, err := store.CreateFromAuthenticationEvent(model.AuthenticationEvent{
		ID: "event", SessionID: "session", TenantID: "tenant", UserID: "user",
		Result: "success", ExpiresAt: &expires,
	}, "policy", "tenant", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.GetActiveAt("session", now); !ok {
		t.Fatal("unexpired authenticated session was rejected")
	}
	if _, ok := store.GetActiveAt("session", now.Add(time.Minute)); ok {
		t.Fatal("session was accepted at its expiration boundary")
	}
	if _, ok := store.Get("session"); !ok {
		t.Fatal("expired session must remain available for reporting")
	}

	invalid := "not-a-time"
	_, err = store.CreateFromAuthenticationEvent(model.AuthenticationEvent{
		ID: "event2", SessionID: "malformed", TenantID: "tenant", UserID: "user",
		Result: "success", ExpiresAt: &invalid,
	}, "policy", "tenant", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.GetActiveAt("malformed", now); ok {
		t.Fatal("malformed expiration was accepted for authorization")
	}
}
