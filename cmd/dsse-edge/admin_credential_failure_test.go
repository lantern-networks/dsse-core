package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

type failingCredentials struct {
	*fakeCredentialPersistence
	fail bool
}

func (p *failingCredentials) Upsert(ctx context.Context, c *localAdminCredential) error {
	if p.fail {
		return fmt.Errorf("private database failure sentinel")
	}
	return p.fakeCredentialPersistence.Upsert(ctx, c)
}
func (p *failingCredentials) Delete(ctx context.Context, tenant, email string) error {
	if p.fail {
		return fmt.Errorf("private database failure sentinel")
	}
	return p.fakeCredentialPersistence.Delete(ctx, tenant, email)
}

func credentialFailureFixture(t *testing.T) (*localAdminCredentialStore, *failingCredentials, string, time.Time) {
	t.Helper()
	p := &failingCredentials{fakeCredentialPersistence: newFakeCredentialPersistence()}
	s, err := newLocalAdminCredentialStoreWithPersistence("DSSE", p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	token, err := s.Invite("alice@example.com", "tenant_test", "adm_test", []string{"admin"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetActivationPassword(token, "test-password-with-length", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.BeginTOTPEnrollment(token, now); err != nil {
		t.Fatal(err)
	}
	return s, p, token, now
}

func TestCredentialMutationsRequireDurableSave(t *testing.T) {
	for _, op := range []string{"invite", "reinvite", "password", "totp_begin", "complete", "suspend", "roles", "delete", "login_totp", "login_recovery"} {
		t.Run(op, func(t *testing.T) {
			s, p, token, now := credentialFailureFixture(t)
			var recovery []string
			if op == "suspend" || op == "roles" || op == "delete" || strings.HasPrefix(op, "login_") {
				code, _ := totpCodeForCounter(s.byEmail["alice@example.com"].TOTPSecret, uint64(now.Unix())/totpPeriod)
				var err error
				recovery, err = s.CompleteActivation(token, code, now)
				if err != nil {
					t.Fatal(err)
				}
			}
			before := cloneCredential(s.byEmail["alice@example.com"])
			mutate := func() error {
				switch op {
				case "invite":
					v, e := s.Invite("new@example.com", "tenant_test", "adm_new", []string{"admin"}, now)
					if e != nil && v != "" {
						t.Fatal("token on failure")
					}
					return e
				case "reinvite":
					_, e := s.Invite("alice@example.com", "tenant_test", "adm_other", []string{"analyst"}, now)
					return e
				case "password":
					return s.SetActivationPassword(token, "replacement-password-value", now)
				case "totp_begin":
					secret, uri, e := s.BeginTOTPEnrollment(token, now)
					if e != nil && (secret != "" || uri != "") {
						t.Fatal("secret on failure")
					}
					return e
				case "complete":
					code, _ := totpCodeForCounter(before.TOTPSecret, uint64(now.Unix())/totpPeriod)
					v, e := s.CompleteActivation(token, code, now)
					if e != nil && len(v) > 0 {
						t.Fatal("recovery codes on failure")
					}
					return e
				case "suspend":
					_, e := s.SetStatus("tenant_test", "adm_test", credentialStatusSuspended, now)
					return e
				case "roles":
					_, e := s.SetRoles("tenant_test", "adm_test", []string{"analyst"}, now)
					return e
				case "delete":
					_, e := s.Delete("tenant_test", "adm_test", now)
					return e
				case "login_totp", "login_recovery":
					code, _ := totpCodeForCounter(before.TOTPSecret, uint64(now.Unix())/totpPeriod)
					if op == "login_recovery" {
						code = recovery[0]
					}
					v, e := s.VerifyTOTP("alice@example.com", code, now)
					if e != nil && v != nil {
						t.Fatal("credential issued on failed save")
					}
					return e
				}
				panic("unknown")
			}
			p.fail = true
			if err := mutate(); !errors.Is(err, errCredentialPersistence) {
				t.Fatalf("expected storage failure, got %v", err)
			}
			if !reflect.DeepEqual(before, s.byEmail["alice@example.com"]) || len(s.byEmail) != 1 {
				t.Fatal("failed mutation changed memory")
			}
			reloaded, e := newLocalAdminCredentialStoreWithPersistence("DSSE", p)
			if e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(before, reloaded.byEmail["alice@example.com"]) || len(reloaded.byEmail) != 1 {
				t.Fatal("failed mutation changed durable state")
			}
			p.fail = false
			if err := mutate(); err != nil {
				t.Fatalf("retry failed: %v", err)
			}
			if op == "login_recovery" {
				if _, err := s.VerifyTOTP("alice@example.com", recovery[0], now); err == nil {
					t.Fatal("recovery code reused")
				}
			}
		})
	}
}

func TestActivationStorageFailureHTTPAndAudit(t *testing.T) {
	for _, route := range []string{"password", "totp/begin", "totp/complete"} {
		t.Run(route, func(t *testing.T) {
			s, p, token, now := credentialFailureFixture(t)
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), LocalCredentials: s})
			code, _ := totpCodeForCounter(s.byEmail["alice@example.com"].TOTPSecret, uint64(now.Unix())/totpPeriod)
			body, _ := json.Marshal(map[string]string{"token": token, "new_password": "replacement-password-value", "code": code})
			p.fail = true
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/activate/"+route, strings.NewReader(string(body))))
			if rec.Code != 503 {
				t.Fatalf("status %d", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "private database") {
				t.Fatal("internal error exposed")
			}
			rows, err := writer.ReadJSONL("audit.log.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0]["result"] != "failure" || rows[0]["tenant_id"] != "tenant_test" || rows[0]["target_id"] != "adm_test" {
				t.Fatalf("wrong audit: %#v", rows)
			}
			p.fail = false
			rec = httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/activate/"+route, strings.NewReader(string(body))))
			if rec.Code != 200 {
				t.Fatalf("retry status %d", rec.Code)
			}
			rows, _ = writer.ReadJSONL("audit.log.jsonl")
			if len(rows) != 2 || rows[1]["result"] != "success" || rows[1]["tenant_id"] != "tenant_test" {
				t.Fatal("retry attribution failed")
			}
		})
	}
}

func TestCredentialBulkDeleteReportsFailures(t *testing.T) {
	s, p, _, _ := credentialFailureFixture(t)
	p.fail = true
	removed, err := s.DeleteAllForTenant("tenant_test")
	if !errors.Is(err, errCredentialPersistence) || len(removed) != 0 || len(s.List("tenant_test")) != 1 {
		t.Fatal("bulk deletion hid failure")
	}
	p.fail = false
	removed, err = s.DeleteAllForTenant("tenant_test")
	if err != nil || len(removed) != 1 || len(s.List("tenant_test")) != 0 {
		t.Fatal("bulk deletion retry failed")
	}
}

func TestCredentialFailedLoginStillLocksDuringStorageOutage(t *testing.T) {
	s, p, token, now := credentialFailureFixture(t)
	code, _ := totpCodeForCounter(s.byEmail["alice@example.com"].TOTPSecret, uint64(now.Unix())/totpPeriod)
	if _, err := s.CompleteActivation(token, code, now); err != nil {
		t.Fatal(err)
	}
	p.fail = true
	for i := 0; i < maxFailedLogins; i++ {
		if _, err := s.VerifyPassword("alice@example.com", "wrong", now); err == nil {
			t.Fatal("bad password accepted")
		}
	}
	if !s.byEmail["alice@example.com"].locked(now) {
		t.Fatal("storage outage weakened lockout")
	}
	if _, err := s.VerifyPassword("alice@example.com", "test-password-with-length", now); err == nil {
		t.Fatal("locked account signed in")
	}
}

func TestAdminAccountStorageFailureHTTPAndAudit(t *testing.T) {
	for _, op := range []string{"invite", "suspend", "reactivate", "roles", "delete"} {
		t.Run(op, func(t *testing.T) {
			p := &failingCredentials{fakeCredentialPersistence: newFakeCredentialPersistence()}
			s, err := newLocalAdminCredentialStoreWithPersistence("DSSE", p)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			seedActiveAdminAccount(t, s, "target@example.com", "tenant_lab_001", "adm_target", []string{"admin"}, now)
			seedActiveAdminAccount(t, s, "keeper@example.com", "tenant_lab_001", "adm_keeper", []string{"admin"}, now)
			if op == "reactivate" {
				if _, err := s.SetStatus("tenant_lab_001", "adm_target", credentialStatusSuspended, now); err != nil {
					t.Fatal(err)
				}
			}
			before := cloneCredential(s.byEmail["target@example.com"])
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			auth, tokens := adminRBACMatrixAuthStore(t)
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), AdminAuth: auth, LocalCredentials: s})
			method, path, body := "POST", "/admin/admins/adm_target/"+op, `{}`
			if op == "invite" {
				path = "/admin/admins/invite"
				body = `{"email":"new@example.com","roles":["admin"]}`
			}
			if op == "roles" {
				body = `{"roles":["analyst"]}`
			}
			if op == "delete" {
				method = "DELETE"
				path = "/admin/admins/adm_target"
			}
			p.fail = true
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+tokens["admin"])
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != 503 {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			if !reflect.DeepEqual(before, s.byEmail["target@example.com"]) || len(s.byEmail) != 2 {
				t.Fatal("HTTP failure changed state")
			}
			rows, err := writer.ReadJSONL("audit.log.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0]["event_type"] != "admin_config_change" || rows[0]["result"] != "error" || rows[0]["tenant_id"] != "tenant_lab_001" || rows[0]["metadata"].(map[string]any)["status_code"] != float64(503) {
				t.Fatalf("wrong mutation audit: %#v", rows)
			}
		})
	}
}
