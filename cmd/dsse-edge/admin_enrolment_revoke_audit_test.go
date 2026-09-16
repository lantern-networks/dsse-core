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

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/enrolltoken"
	"github.com/lantern-networks/dsse-core/logs"
)

type enrolmentAuditPersister struct {
	data    []byte
	fail    bool
	saveErr error
}

func (p *enrolmentAuditPersister) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *enrolmentAuditPersister) Save(b []byte) error {
	if p.fail {
		return errors.New("private storage detail")
	}
	p.data = bytes.Clone(b)
	return p.saveErr
}

func TestEnrolmentRevokeHTTPStateAndAudit(t *testing.T) {
	for _, mode := range []string{"success", "foreign", "denied", "already_revoked", "save_failure", "unconfirmed", "bridge", "synced_in_place"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			tenant := testEvaluator().PolicyBundle.TenantID
			p := &enrolmentAuditPersister{}
			tokens := enrolltoken.NewStore()
			tokens.SetPersister(p)
			tokenTenant := tenant
			if mode == "foreign" {
				tokenTenant = "other-tenant"
			}
			tok, secret, err := tokens.Issue(enrolltoken.DefaultPolicy(), tokenTenant, "", "private token label", "issuer", "", now.Add(time.Hour), now)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "already_revoked" {
				tokens.Revoke(tok.ID, "previous", now)
			}
			before := tokens.List(tokenTenant)[0]
			roles := []string{"admin"}
			if mode == "denied" {
				roles = []string{"analyst"}
			}
			creds := newLocalAdminCredentialStore("DSSE")
			seedActiveAdminAccount(t, creds, "review@example.test", tenant, "reviewer", roles, now)
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(principalFromCredential(creds.byEmail["review@example.test"], now))
			auth.UpsertSession(adminSession{ID: "review-session", TenantID: tenant, AdminPrincipalID: "reviewer", Roles: roles, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "review-csrf"}})
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, LocalCredentials: creds, EnrolmentTokens: tokens, EnrolledLedger: enrolledinventory.NewLedger()})
			p.fail = mode == "save_failure"
			if mode == "unconfirmed" {
				p.saveErr = blobstore.ErrDurabilityUnconfirmed
			}
			if mode == "bridge" {
				p.saveErr = errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
			}
			if mode == "synced_in_place" {
				p.saveErr = blobstore.ErrSavedWithoutAtomicity
			}
			path := "/admin/enrolment-tokens/" + tok.ID + "/revoke"
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
			req.AddCookie(&http.Cookie{Name: "admin_session", Value: "review-session"})
			req.Header.Set("X-CSRF-Token", "review-csrf")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			want := map[string]int{"success": 200, "foreign": 404, "denied": 403, "already_revoked": 409, "save_failure": 503, "unconfirmed": 503, "bridge": 503, "synced_in_place": 200}[mode]
			if rec.Code != want {
				t.Fatalf("status %d expected %d: %s", rec.Code, want, rec.Body.String())
			}
			after := tokens.List(tokenTenant)[0]
			if mode == "success" || mode == "synced_in_place" {
				if after.RevokedAt == "" || after.RevokedBy != "reviewer" {
					t.Fatal("revocation not attributed")
				}
			} else if after != before {
				t.Fatal("refused mutation changed token")
			}
			rows, err := writer.ReadJSONL("audit.log.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			event, result, target := "admin_config_change", "error", path
			if mode == "success" || mode == "synced_in_place" {
				result = "success"
			}
			if mode == "denied" {
				event, result, target = "admin_rbac_denied", "failure", "admin.enrollment.write"
			}
			count := 0
			for _, row := range rows {
				if row["event_type"] != event {
					continue
				}
				count++
				if row["result"] != result || row["target_id"] != target || row["tenant_id"] != tenant || row["actor_user_id"] != "reviewer" || row["timestamp"] == nil {
					t.Fatalf("wrong audit: %#v", row)
				}
				encoded, _ := json.Marshal(row)
				for _, s := range []string{secret, "private token label", "private storage detail", "review-csrf"} {
					if bytes.Contains(encoded, []byte(s)) {
						t.Fatal("audit leaked private material")
					}
				}
			}
			if count != 1 {
				t.Fatalf("expected one %s audit, got %d", event, count)
			}
			if strings.Contains(rec.Body.String(), "private storage detail") {
				t.Fatal("response leaked storage detail")
			}
			if mode == "save_failure" || mode == "unconfirmed" || mode == "bridge" {
				if tokens.Health() == nil {
					t.Fatal("store not stopped")
				}
				if _, err := tokens.Verify(secret, tokenTenant, now); !errors.Is(err, enrolltoken.ErrStateUnavailable) {
					t.Fatal("unavailable store accepts token")
				}
			}
		})
	}
}

func TestTenantErasureReportsEnrolmentPersistenceFailure(t *testing.T) {
	p := &enrolmentAuditPersister{}
	s := enrolltoken.NewStore()
	s.SetPersister(p)
	now := time.Now()
	if _, _, err := s.Issue(enrolltoken.DefaultPolicy(), "tenant", "", "label", "admin", "", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	p.fail = true
	result := &adminTenantPurgeResult{TenantID: "tenant"}
	(adminTenantExtraStores{EnrolmentTokens: s}).erase(result)
	if len(result.Failures) != 1 || len(result.Erased) != 0 || s.CountForTenant("tenant") != 1 {
		t.Fatalf("false erasure outcome: %+v", result)
	}
}
