package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

func newCaseDistinctTokenAdminFixture(t *testing.T) (*enrolltoken.Store, enrolltoken.Token, string, *http.ServeMux) {
	t.Helper()
	now := time.Now().UTC()
	tokens := enrolltoken.NewStore()
	foreign, secret, err := tokens.Issue(enrolltoken.DefaultPolicy(), "tenanta", "", "foreign token", "admin", "", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerAdminEnrolmentTokenEndpoints(mux, tokens, enrolltoken.DefaultPolicy(),
		func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, nil,
		func(_, _ string) string { return "" }, "", nil, nil, "", "")
	return tokens, foreign, secret, mux
}

func callCaseDistinctTokenAdmin(mux *http.ServeMux, method, path string) *httptest.ResponseRecorder {
	r := requestWithAdminIdentity(httptest.NewRequest(method, path, nil),
		adminIdentity{PrincipalID: "admin", TenantID: "TenantA"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestEnrolmentTokenAdminCannotReadRevokeOrEraseCaseDistinctTenant(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		_, _, _, mux := newCaseDistinctTokenAdminFixture(t)
		w := callCaseDistinctTokenAdmin(mux, http.MethodGet, "/admin/enrolment-tokens")
		if w.Code != http.StatusOK {
			t.Fatalf("list status = %d", w.Code)
		}
		var listed struct {
			Tokens []enrolltoken.Token `json:"tokens"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
			t.Fatal(err)
		}
		if len(listed.Tokens) != 0 {
			t.Fatal("case-distinct organization's token was listed for this administrator")
		}
	})
	t.Run("revoke", func(t *testing.T) {
		tokens, foreign, secret, mux := newCaseDistinctTokenAdminFixture(t)
		if w := callCaseDistinctTokenAdmin(mux, http.MethodPost, "/admin/enrolment-tokens/"+foreign.ID+"/revoke"); w.Code != http.StatusNotFound {
			t.Fatalf("foreign revoke status = %d, want 404", w.Code)
		}
		if _, err := tokens.Verify(secret, "tenanta", time.Now()); err != nil {
			t.Fatalf("foreign token changed after rejected revoke: %v", err)
		}
	})
	t.Run("verify", func(t *testing.T) {
		tokens, _, secret, _ := newCaseDistinctTokenAdminFixture(t)
		if _, err := tokens.Verify(secret, "TenantA", time.Now()); !errors.Is(err, enrolltoken.ErrWrongTenant) {
			t.Fatalf("case-distinct tenant verified foreign token: %v", err)
		}
	})
	t.Run("footprint", func(t *testing.T) {
		tokens, _, _, _ := newCaseDistinctTokenAdminFixture(t)
		if n := tokens.CountForTenant("TenantA"); n != 0 {
			t.Fatalf("foreign token counted in this tenant's footprint: %d", n)
		}
	})
	t.Run("erase", func(t *testing.T) {
		tokens, _, secret, _ := newCaseDistinctTokenAdminFixture(t)
		if n := tokens.RemoveTenant("TenantA"); n != 0 {
			t.Fatalf("retiring this tenant erased %d foreign tokens", n)
		}
		if _, err := tokens.Verify(secret, "tenanta", time.Now()); err != nil {
			t.Fatalf("foreign token lost after other tenant retirement: %v", err)
		}
	})
}

func TestEnrolmentTokenWhitespaceFilterDoesNotListEveryTenant(t *testing.T) {
	tokens, _, _, _ := newCaseDistinctTokenAdminFixture(t)
	if got := tokens.List("   "); len(got) != 0 {
		t.Fatal("whitespace-only tenant filter became a deployment-wide token listing")
	}
}
