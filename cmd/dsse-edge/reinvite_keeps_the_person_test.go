package main

import (
	"strings"
	"testing"
	"time"
)

// ★★★ A RE-INVITE MADE A SECOND PERSON, AND THEN NOBODY COULD SIGN IN (2026-08-20, measured on a real customer
// account while setting up a cross-tenant isolation run).
//
// Re-inviting an address already in this organization is deliberately allowed — it is how a lost activation
// link is reissued. It also minted a new principal id and wrote it over the credential, while the principal
// already recorded for that person kept the old one. Their identity here is (organization, IdP, subject); the
// database says so with a unique index on exactly those three. So the next sign-in tried to insert a SECOND
// principal for the same person, the index refused, and the customer's screen showed
//
//	pq: duplicate key value violates unique constraint "admin_principals_subject_unique_idx"
//
// From then on that administrator could never sign in again. The workaround had been written down as a rule —
// "do not re-invite an address that already has a principal" — which is a rule nobody can be expected to know.
func TestAReInviteKeepsTheSamePerson(t *testing.T) {
	store := newLocalAdminCredentialStore("lab")
	if _, err := store.Invite("someone@lab.local", "tenant_acme", "adm_first", []string{"admin"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	first, ok := store.byEmail["someone@lab.local"]
	if !ok || first.PrincipalID != "adm_first" {
		t.Fatalf("the invite did not record the person: %+v", first)
	}

	// The activation link is lost, so it is reissued. That is the same person.
	if _, err := store.Invite("someone@lab.local", "tenant_acme", "adm_second", []string{"admin"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := store.byEmail["someone@lab.local"].PrincipalID; got != "adm_first" {
		t.Fatalf("re-issuing an activation link renamed the person to %q — the principal already recorded keeps "+
			"the old name, and the next sign-in becomes a second person the database refuses", got)
	}

	// And a sign-in adopts whatever this organization already knows them by, so a deployment where the two
	// have ALREADY diverged recovers without anybody editing a database.
	cred := &localAdminCredential{Email: "someone@lab.local", TenantID: "tenant_acme", PrincipalID: "adm_drifted",
		Roles: []string{"admin"}}
	principal := principalFromCredentialResolved(cred, time.Now(), func(tenantID, subject string) (string, bool) {
		if tenantID == "tenant_acme" && strings.EqualFold(subject, "someone@lab.local") {
			return "adm_known", true
		}
		return "", false
	})
	if principal.ID != "adm_known" {
		t.Fatalf("sign-in used %q instead of the id this organization already knows this person by", principal.ID)
	}

	// With nothing recorded, the credential's own id stands — a first sign-in must still work.
	fresh := principalFromCredentialResolved(cred, time.Now(), func(string, string) (string, bool) { return "", false })
	if fresh.ID != "adm_drifted" {
		t.Fatalf("a first sign-in lost the credential's id: %q", fresh.ID)
	}
}
