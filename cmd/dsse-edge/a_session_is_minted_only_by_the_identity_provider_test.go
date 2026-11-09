package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/session"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// Security review S1 (2026-11-07). POST /auth/events let a caller holding nothing more than a connector's
// credentials mint a live session whose id, user and MFA state were the caller's own words; the application
// routes and the decision evaluator then read that session as if the identity provider had issued it. These
// tests pin the two halves of the fix: a production node has no such route, and a session id is never read
// from the query string.

func forgedAuthenticationEvent(tenant string) string {
	return `{"id":"auth-forged","session_id":"forged","tenant_id":"` + tenant + `","user_id":"someone-important","mfa_state":"satisfied","result":"success"}`
}

func forgedSessionRequest(t *testing.T, labMode bool, tenant string) (http.Handler, *session.Store, func() *httptest.ResponseRecorder) {
	t.Helper()
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "s1-other", 91)
	reg, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{"tenant_other": ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chain := leafSignedBy(t, ca, "conn-other", reg.Pool)
	if len(chain) == 0 {
		t.Fatal("connector certificate did not verify")
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sessions := session.NewStore()
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(),
		SessionStore: sessions, TenantCARegistry: reg, LabMode: boolPtr(labMode),
	})
	return handler, sessions, func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/auth/events", strings.NewReader(forgedAuthenticationEvent(tenant)))
		r.Header.Set(connectorIDHeader, "conn-other")
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chain[0][0]}, VerifiedChains: chain}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
}

func TestAProductionNodeDoesNotMintSessionsFromAConnectorsWords(t *testing.T) {
	_, sessions, post := forgedSessionRequest(t, false, "tenant_other")
	if w := post(); w.Code != http.StatusNotFound {
		t.Fatalf("a production node answered POST /auth/events with %d, want 404: %s", w.Code, w.Body.String())
	}
	if _, ok := sessions.Get("forged"); ok {
		t.Fatal("a session was minted from a connector's authentication event on a production node")
	}
}

func TestALabHarnessMayStillSeedASession(t *testing.T) {
	// A lab node answers for its seed tenant; the harness seeds a session there.
	_, sessions, post := forgedSessionRequest(t, true, "tenant_lab_001")
	if w := post(); w.Code != http.StatusCreated {
		t.Fatalf("lab seeding answered %d: %s", w.Code, w.Body.String())
	}
	if _, ok := sessions.Get("forged"); !ok {
		t.Fatal("lab seeding did not create the session")
	}
}

func TestASessionIdIsNotReadFromTheQueryString(t *testing.T) {
	r := httptest.NewRequest(http.MethodConnect, "/apps/app?session_id=from-query", nil)
	if got := sessionIDFromRequest(r); got != "" {
		t.Fatalf("session id read from the query string: %q", got)
	}
	r.Header.Set("x-session-id", "from-header")
	if got := sessionIDFromRequest(r); got != "from-header" {
		t.Fatalf("header session id: %q", got)
	}
}
