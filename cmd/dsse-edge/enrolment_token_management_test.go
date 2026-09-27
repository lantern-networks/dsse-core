package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/enrolltoken"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestPostgresEnrolmentManagementStateAndAudit(t *testing.T) {
	db := openEnrolmentTokenDB(t)
	s := newPostgresEnrolmentTokenStore(db)
	now := time.Now().UTC()
	tenant := "tenant_test_management"
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "reviewer", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "sql-session", TenantID: tenant, AdminPrincipalID: "reviewer", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "sql-csrf"}})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, EnrolmentTokens: s, EnrolledLedger: enrolledinventory.NewLedger()})
	issue := func(tenant string) enrolltoken.Token {
		t.Helper()
		tok, _, err := s.Issue(enrolltoken.DefaultPolicy(), tenant, "", "management test", "issuer", "", now.Add(time.Hour), now)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	own, foreign := issue(tenant), issue("tenant_test_foreign")
	call := func(method, path string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader("{}"))
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "sql-session"})
		r.Header.Set("X-CSRF-Token", "sql-csrf")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: %d want %d: %s", method, path, w.Code, want, w.Body)
		}
		return w
	}
	path := "/admin/enrolment-tokens/" + own.ID + "/revoke"
	call("POST", "/admin/enrolment-tokens/"+foreign.ID+"/revoke", 404)
	if _, err = db.Exec(`ALTER TABLE enrolment_tokens ADD CONSTRAINT review_revoke_failure CHECK(revoked_at IS NULL) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(`ALTER TABLE enrolment_tokens DROP CONSTRAINT IF EXISTS review_revoke_failure`) })
	call("POST", path, 503)
	if rows, err := s.ListContext(t.Context(), tenant); err != nil || len(rows) != 1 || rows[0].RevokedAt != "" {
		t.Fatalf("failed revoke changed authority: %v %v", rows, err)
	}
	if _, err = db.Exec(`ALTER TABLE enrolment_tokens DROP CONSTRAINT review_revoke_failure`); err != nil {
		t.Fatal(err)
	}
	call("POST", path, 200)
	call("POST", path, 409)
	rows, err := newPostgresEnrolmentTokenStore(db).ListContext(t.Context(), tenant)
	if err != nil || len(rows) != 1 || rows[0].RevokedBy != "reviewer" {
		t.Fatalf("peer did not see revoke: %v %v", rows, err)
	}
	if rows, err := s.ListContext(t.Context(), foreign.TenantID); err != nil || len(rows) != 1 || rows[0].RevokedAt != "" {
		t.Fatal("foreign changed")
	}
	var body struct {
		Tokens      []enrolltoken.Token `json:"tokens"`
		Outstanding int                 `json:"outstanding"`
		Expiring    []enrolltoken.Token `json:"expiring_within_48h"`
	}
	if err := json.Unmarshal(call("GET", "/admin/enrolment-tokens", 200).Body.Bytes(), &body); err != nil || len(body.Tokens) != 1 || body.Outstanding != 0 || len(body.Expiring) != 0 {
		t.Fatalf("snapshot: %+v %v", body, err)
	}
	// A database outage must not look like an empty inventory or a missing token.
	db.Close()
	call("GET", "/admin/enrolment-tokens", 503)
	call("POST", path, 503)
	audits, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	successes, failures := 0, 0
	for _, a := range audits {
		if a["event_type"] != "admin_config_change" {
			continue
		}
		if a["actor_user_id"] != "reviewer" || a["tenant_id"] != tenant {
			t.Fatalf("wrong actor: %v", a)
		}
		if a["result"] == "success" {
			successes++
		} else {
			failures++
		}
	}
	if successes != 1 || failures != 4 {
		t.Fatalf("audit outcomes success=%d failure=%d", successes, failures)
	}
}

func TestPostgresEnrolmentRevokeCapturedTerm(t *testing.T) {
	leader, peer := postgresFailureElectors(t)
	db := openEnrolmentTokenDB(t)
	s := newPostgresEnrolmentTokenStore(db)
	now := time.Now().UTC()
	tok, _, err := s.Issue(enrolltoken.DefaultPolicy(), "tenant_test_term", "", "", "issuer", "", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	old := cpLeaderElectorInstance
	defer func() { cpLeaderElectorInstance = old }()
	cpLeaderElectorInstance = leader
	leader.tick()
	if !leader.IsLeader() {
		t.Fatal("election")
	}
	ctx := captureCPWriteLease(t.Context())
	leader.release()
	peer.tick()
	if !peer.IsLeader() {
		t.Fatal("peer election")
	}
	peer.release()
	leader.tick()
	if _, ok, err := s.RevokeForTenantContext(ctx, tok.TenantID, tok.ID, "reviewer", now); err == nil || ok {
		t.Fatal("old term accepted")
	}
	rows, err := s.ListContext(t.Context(), tok.TenantID)
	if err != nil || len(rows) != 1 || rows[0].RevokedAt != "" {
		t.Fatal("old term modified row")
	}
	if _, ok, err := s.RevokeForTenantContext(captureCPWriteLease(t.Context()), "foreign", tok.ID, "reviewer", now); err != nil || ok {
		t.Fatal("foreign tenant accepted")
	}
	if _, ok, err := s.RevokeForTenantContext(captureCPWriteLease(t.Context()), tok.TenantID, tok.ID, "reviewer", now); err != nil || !ok {
		t.Fatalf("new term rejected: %v", err)
	}
}
