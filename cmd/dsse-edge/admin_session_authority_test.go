package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestIntrospector(t *testing.T, url string) *sessionIntrospector {
	t.Helper()
	s, err := newSessionIntrospector(url, "") // system roots; httptest server is plain HTTP
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIntrospectAcceptsValidSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Cookie"); got != "admin_session=sess-123" {
			t.Errorf("authority did not receive the forwarded cookie, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tenant_id":"t1","principal_id":"adm_9","roles":["admin"],"scopes":["s1"],"auth_method":"admin_session","csrf_token":"csrf-xyz"}`))
	}))
	defer srv.Close()

	id, ok := newTestIntrospector(t, srv.URL).introspect(t.Context(), "sess-123")
	if !ok {
		t.Fatal("expected the session to be accepted")
	}
	if id.PrincipalID != "adm_9" || id.TenantID != "t1" || id.AuthMethod != "admin_session" || id.CSRFToken != "csrf-xyz" {
		t.Fatalf("identity not built from authority response: %+v", id)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "admin" {
		t.Fatalf("roles not carried: %+v", id.Roles)
	}
}

func TestIntrospectRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	if _, ok := newTestIntrospector(t, srv.URL).introspect(t.Context(), "bad"); ok {
		t.Fatal("a 401 from the authority must be rejected (fail-closed)")
	}
}

func TestIntrospectRejectsNonSessionAuthMethod(t *testing.T) {
	// A bearer/api-token resolution echoed back must NOT be accepted as a session identity.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"principal_id":"adm_legacy_token","auth_method":"legacy_admin_token"}`))
	}))
	defer srv.Close()
	if _, ok := newTestIntrospector(t, srv.URL).introspect(t.Context(), "x"); ok {
		t.Fatal("non-session auth_method must be rejected")
	}
}

func TestIntrospectFailsClosedOnUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now unreachable
	if _, ok := newTestIntrospector(t, url).introspect(t.Context(), "x"); ok {
		t.Fatal("an unreachable authority must fail closed")
	}
}
