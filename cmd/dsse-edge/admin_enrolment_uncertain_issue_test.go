package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/enrolltoken"
	"github.com/lantern-networks/dsse-core/logs"
)

type uncertainEnrolmentPersister struct {
	data      []byte
	committed bool
}

func (p *uncertainEnrolmentPersister) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *uncertainEnrolmentPersister) Save(b []byte) error {
	if p.committed {
		p.data = bytes.Clone(b)
	}
	return errors.New("private storage acknowledgement lost")
}

func TestEnrolmentEmptyPartialDoesNotProveNoDurableIssue(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unsaved", true: "committed_error"}[committed], func(t *testing.T) {
			now := time.Now().UTC()
			tenant := testEvaluator().PolicyBundle.TenantID
			p := &uncertainEnrolmentPersister{committed: committed}
			tokens := enrolltoken.NewStore()
			tokens.SetPersister(p)
			creds := newLocalAdminCredentialStore("DSSE")
			seedActiveAdminAccount(t, creds, "review@example.test", tenant, "reviewer", []string{"admin"}, now)
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(principalFromCredential(creds.byEmail["review@example.test"], now))
			auth.UpsertSession(adminSession{ID: "review-session", TenantID: tenant, AdminPrincipalID: "reviewer", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "review-csrf"}})
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, LocalCredentials: creds, EnrolmentTokens: tokens, EnrolledLedger: enrolledinventory.NewLedger()})
			request := func(method, path, body string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(method, path, strings.NewReader(body))
				req.AddCookie(&http.Cookie{Name: "admin_session", Value: "review-session"})
				req.Header.Set("X-CSRF-Token", "review-csrf")
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				return rec
			}
			rec := request("POST", "/admin/enrolment-tokens", `{"label":"private label","count":3,"expires_in_hours":24}`)
			if rec.Code != 409 {
				t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
			}
			var body struct {
				Partial bool              `json:"partial"`
				Tokens  []json.RawMessage `json:"tokens"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if !body.Partial || len(body.Tokens) != 0 {
				t.Fatal("failed first issue unexpectedly disclosed credentials")
			}
			if len(tokens.List(tenant)) != 0 || !errors.Is(tokens.Health(), enrolltoken.ErrStateUnavailable) {
				t.Fatal("uncertain state was published or health not latched")
			}
			persisted := enrolltoken.NewStore()
			persisted.SetPersister(p)
			want := 0
			if committed {
				want = 1
			}
			if len(persisted.List(tenant)) != want {
				t.Fatal("durable result differs from injected commit outcome")
			}
			before := bytes.Clone(p.data)
			if next := request("POST", "/admin/enrolment-tokens", `{"count":1}`); next.Code != 503 {
				t.Fatalf("retry: %d", next.Code)
			}
			if !bytes.Equal(before, p.data) {
				t.Fatal("retry overwrote uncertain saved state")
			}
			if list := request("GET", "/admin/enrolment-tokens", ""); list.Code != 503 {
				t.Fatalf("unknown registry was displayed as usable: %d", list.Code)
			}
			rows, err := writer.ReadJSONL("audit.log.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, a := range rows {
				if a["event_type"] == "admin_config_change" {
					count++
					if a["result"] != "error" || a["actor_user_id"] != "reviewer" || a["tenant_id"] != tenant {
						t.Fatal("wrong failure audit attribution")
					}
				}
			}
			if count != 2 {
				t.Fatalf("mutation error audits: %d", count)
			}
			audit, _ := json.Marshal(rows)
			for _, secret := range []string{"private label", "private storage acknowledgement lost", "review-csrf"} {
				if bytes.Contains(audit, []byte(secret)) || bytes.Contains(rec.Body.Bytes(), []byte(secret)) {
					t.Fatal("private detail exposed")
				}
			}
		})
	}
}
