package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

type recordingTokenStore struct {
	written    []adminAPIToken
	principals []adminPrincipal
	err        error
}

func (s *recordingTokenStore) PersistPrincipal(_ context.Context, p adminPrincipal) error {
	if s.err != nil {
		return s.err
	}
	s.principals = append(s.principals, p)
	return nil
}

func (s *recordingTokenStore) PersistAPIToken(_ context.Context, token adminAPIToken) error {
	if s.err != nil {
		return s.err
	}
	s.written = append(s.written, token)
	return nil
}

// ★★★ THE BOOTSTRAP FOR A TIME-BOXED DOOR MUST ITSELF BE TIME-BOXED (decided 2026-08-20).
//
// This mints the credential that can act across organizations — the one thing in the system that a customer
// cannot see coming, which is why the envelope wraps it in a standing delegation they can withdraw and an
// elevation that expires. A bootstrap that handed out something permanent would put a permanent key beside a
// temporary door, and nobody would ever notice, because it works.
//
// So the refusals are the substance here, and each one is a way the credential could outlive its reason.
func TestTheOperatorBootstrapIssuesSomethingThatExpiresAndNamesWhoTookIt(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	store := &recordingTokenStore{}
	deps := operatorBootstrapDeps{OperatorTenantID: "tenant_operator_001", Store: store,
		Now: func() time.Time { return now }}

	if _, _, err := mintOperatorBootstrapCredential(context.Background(), deps, time.Hour, "   "); err == nil {
		t.Fatal("a cross-organization credential was issued with nobody named on it — afterwards there is no " +
			"one to ask what it was for")
	}
	if _, _, err := mintOperatorBootstrapCredential(context.Background(), deps, 0, "why"); err == nil {
		t.Fatal("a credential with no expiry was issued for a door that is time-boxed by design")
	}
	if _, _, err := mintOperatorBootstrapCredential(context.Background(), deps, 72*time.Hour, "why"); err == nil {
		t.Fatal("three days was issued: the elevation this opens is measured in hours, and a bootstrap that " +
			"outlives it is the permanent key the envelope exists to avoid")
	}
	if len(store.written) != 0 {
		t.Fatalf("a refused mint still wrote something: %+v", store.written)
	}

	// Not on a control plane: nothing to act across.
	noTenant := deps
	noTenant.OperatorTenantID = ""
	if _, _, err := mintOperatorBootstrapCredential(context.Background(), noTenant, time.Hour, "why"); err == nil {
		t.Fatal("a node that does not know which organization is the operator's minted a cross-organization credential")
	}

	// No durable store: a credential that dies with the process is worse than none, because somebody will
	// believe they have one.
	noStore := deps
	noStore.Store = nil
	if _, _, err := mintOperatorBootstrapCredential(context.Background(), noStore, time.Hour, "why"); err == nil {
		t.Fatal("a credential was minted into memory on a node with no durable store")
	}

	token, raw, err := mintOperatorBootstrapCredential(context.Background(), deps, 2*time.Hour, "PKI delegation walk")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(store.written) != 1 {
		t.Fatalf("the credential was not persisted: %d written", len(store.written))
	}
	// ★ AND THE PRINCIPAL IT IS ATTRIBUTED TO. The lookup joins every token to an ACTIVE creator, so a
	// credential minted without one is stored, unexpired, and refused on every plane — 401 forever, with
	// nothing saying why. That has now been found twice; this is the assertion that ends it.
	if len(store.principals) != 1 || store.principals[0].ID != token.CreatedByAdminPrincipalID {
		t.Fatalf("the credential names a creator that was never written: created_by=%q principals=%+v",
			token.CreatedByAdminPrincipalID, store.principals)
	}
	if store.principals[0].Status != "active" || store.principals[0].TenantID != token.TenantID {
		t.Fatalf("the creator is not an active principal of the credential's organization: %+v", store.principals[0])
	}
	if token.TenantID != "tenant_operator_001" {
		t.Fatalf("minted into the wrong organization: %q", token.TenantID)
	}
	if token.ExpiresAt != now.Add(2*time.Hour).Format(time.RFC3339) {
		t.Fatalf("the expiry is not the one asked for: %q", token.ExpiresAt)
	}
	if !strings.Contains(token.Name, "PKI delegation walk") || token.Metadata["reason"] != "PKI delegation walk" {
		t.Fatalf("the reason is not recorded on the credential: %+v", token)
	}
	if strings.TrimSpace(raw) == "" || strings.Contains(token.TokenHash, raw) {
		t.Fatal("the stored record must hold a hash, and the secret must come back to the caller to be shown once")
	}
	// ★ It must actually be able to cross organizations, or the whole exercise mints something that cannot
	// walk the door it was made for.
	if !adminPermissionAllowed(token.Roles, "admin.tenant.admin") {
		t.Fatalf("the minted credential cannot act across organizations: roles=%v", token.Roles)
	}

	// A store that refuses must not report success — somebody would walk away believing they hold a credential.
	failing := deps
	failing.Store = &recordingTokenStore{err: context.DeadlineExceeded}
	if _, _, err := mintOperatorBootstrapCredential(context.Background(), failing, time.Hour, "why"); err == nil {
		t.Fatal("a credential that could not be written was reported as minted")
	}
}
