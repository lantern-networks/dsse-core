package session

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// TestCreateRequiresExplicitSuccess pins fail-open review finding #16: a session may be minted only from an
// EXPLICITLY successful auth. An empty result (an auth event that proved nothing) must NOT create an active
// session; only result == "success" does.
func TestCreateRequiresExplicitSuccess(t *testing.T) {
	now := time.Now().UTC()
	s := NewStore()
	base := model.AuthenticationEvent{ID: "ae1", SessionID: "s1", TenantID: "acme", UserID: "u1"}

	// empty result -> rejected (was: created an active session).
	if _, err := s.CreateFromAuthenticationEvent(base, "pb1", "acme", now); err == nil {
		t.Fatal("empty auth result must NOT create a session (fail-open #16)")
	}
	// explicit failure -> rejected (unchanged).
	fail := base
	fail.Result = "failure"
	if _, err := s.CreateFromAuthenticationEvent(fail, "pb1", "acme", now); err == nil {
		t.Fatal("failed auth result must not create a session")
	}
	// explicit success -> created (control).
	ok := base
	ok.Result = "success"
	if _, err := s.CreateFromAuthenticationEvent(ok, "pb1", "acme", now); err != nil {
		t.Fatalf("explicit success must create a session: %v", err)
	}
}
