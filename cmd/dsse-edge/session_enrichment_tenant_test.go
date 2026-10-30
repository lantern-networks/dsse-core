package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	sessionstore "github.com/lantern-networks/dsse-core/session"
)

func TestSessionEnrichmentCannotBorrowAnotherTenantsIdentity(t *testing.T) {
	s := sessionstore.NewStore()
	_, err := s.CreateFromAuthenticationEvent(model.AuthenticationEvent{
		ID: "event", SessionID: "session", TenantID: "Acme", UserID: "private-user",
		Result: "success", MFAState: "fresh", AMR: []string{"passkey"},
		AuthTime: time.Now().UTC().Format(time.RFC3339), Metadata: map[string]any{"groups": []string{"private-group"}},
	}, "bundle", "Acme", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"acme", "unrelated"} {
		got := enrichDecisionRequestWithSession(model.DecisionRequest{TenantID: tenant, SessionID: "session"}, s)
		if got.UserID != "" || got.AuthenticationEventID != "" || got.MFAState != "" || got.AuthTime != "" || len(got.AMR) != 0 || len(got.UserGroups) != 0 {
			t.Errorf("%s borrowed other tenant identity: %+v", tenant, got)
		}
	}
	for _, tenant := range []string{"Acme", ""} {
		got := enrichDecisionRequestWithSession(model.DecisionRequest{TenantID: tenant, SessionID: "session"}, s)
		if got.TenantID != "Acme" || got.UserID != "private-user" || got.MFAState != "fresh" {
			t.Errorf("matching session not enriched: %+v", got)
		}
	}
}
