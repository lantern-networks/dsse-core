package main

import (
	"testing"
	"time"
)

func TestFirstPartyPrincipalDoesNotAdoptFederatedSubject(t *testing.T) {
	s := newAdminAuthStore()
	s.UpsertPrincipal(adminPrincipal{ID: "federated-person", TenantID: "tenant", IDPID: "external-idp", Subject: "alice@example.test", Status: "active"})
	cred := &localAdminCredential{PrincipalID: "local-person", TenantID: "tenant", Email: "alice@example.test", Roles: []string{"analyst"}}
	p := principalFromCredentialResolved(cred, time.Now(), s.PrincipalIDForSubject)
	if p.ID != cred.PrincipalID {
		t.Fatalf("local sign-in adopted another IdP's principal: %q", p.ID)
	}
	s.UpsertPrincipal(adminPrincipal{ID: "previous-local-person", TenantID: "tenant", IDPID: "first_party", Subject: "ALICE@example.test", Status: "active"})
	p = principalFromCredentialResolved(cred, time.Now(), s.PrincipalIDForSubject)
	if p.ID != "previous-local-person" {
		t.Fatalf("same first-party account was not preserved: %q", p.ID)
	}
}
