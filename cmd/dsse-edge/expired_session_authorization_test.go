package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	sessionstore "github.com/lantern-networks/dsse-core/session"
)

func TestExpiredSessionCannotAuthenticateClientlessOrEnrichDecision(t *testing.T) {
	now := time.Now().UTC()
	expired := now.Add(-time.Minute).Format(time.RFC3339)
	store := sessionstore.NewStore()
	_, err := store.CreateFromAuthenticationEvent(model.AuthenticationEvent{
		ID: "event", SessionID: "expired-session", TenantID: "tenant", UserID: "user",
		Result: "success", ExpiresAt: &expired,
	}, "policy", "tenant", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/clientless/apps/wiki", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "expired-session"})
	if _, ok := activeSessionFromRequest(req, store); ok {
		t.Fatal("expired session authenticated the clientless browser")
	}
	decision := enrichDecisionRequestWithSession(model.DecisionRequest{SessionID: "expired-session"}, store)
	if decision.UserID != "" || decision.TenantID != "" {
		t.Fatal("expired session supplied identity to a policy decision")
	}
}
