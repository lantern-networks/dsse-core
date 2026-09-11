package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

// End-to-end first-party onboarding + login over the real HTTP handlers: invite -> activation link -> set
// password -> enroll TOTP -> activate -> login (email+password then TOTP) -> admin_session whose identity is
// the operator's email. Proves the operator user ID is attributed to the session.
func TestFirstPartyOnboardingAndLoginEndpoints(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	adminAuth, rawTokensByRole := adminRBACMatrixAuthStore(t)
	handler := newServerWithConfig(serverConfig{
		Evaluator:        testEvaluator(),
		Writer:           writer,
		Registry:         connector.NewRegistry(),
		AdminAuth:        adminAuth,
		LocalCredentials: newLocalAdminCredentialStore("Lantern DSSE"),
	})

	do := func(method, path, bearer, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if bearer != "" {
			req.Header.Set("authorization", "Bearer "+bearer)
		}
		if body != "" {
			req.Header.Set("content-type", "application/json")
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	decode := func(rec *httptest.ResponseRecorder) map[string]any {
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return m
	}
	totpNow := func(secret string) string {
		code, _ := totpCodeForCounter(secret, uint64(time.Now().Unix())/totpPeriod)
		return code
	}

	email := "alice@corp.example.com"

	// 1) invite (admin has admin.accounts.write); analyst is denied
	if rec := do(http.MethodPost, "/admin/admins/invite", rawTokensByRole["analyst"], `{"email":"x@y.com"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst invite: want 403, got %d", rec.Code)
	}
	rec := do(http.MethodPost, "/admin/admins/invite", rawTokensByRole["admin"], `{"email":"`+email+`","roles":["admin"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite: want 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	link, _ := decode(rec)["activation_link"].(string)
	idx := strings.Index(link, "activate=")
	if idx < 0 {
		t.Fatalf("activation_link missing token: %q", link)
	}
	token := link[idx+len("activate="):]

	// 2) activation: validate token, set password, enroll TOTP, complete
	if rec := do(http.MethodGet, "/admin/activate?token="+token, "", ""); rec.Code != http.StatusOK {
		t.Fatalf("activate GET: want 200, got %d", rec.Code)
	}
	if rec := do(http.MethodPost, "/admin/activate/password", "", `{"token":"`+token+`","new_password":"a-strong-passphrase-123"}`); rec.Code != http.StatusOK {
		t.Fatalf("set password: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	rec = do(http.MethodPost, "/admin/activate/totp/begin", "", `{"token":"`+token+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("totp begin: want 200, got %d", rec.Code)
	}
	secret, _ := decode(rec)["secret"].(string)
	if secret == "" {
		t.Fatalf("no totp secret returned")
	}
	if rec := do(http.MethodPost, "/admin/activate/totp/complete", "", `{"token":"`+token+`","code":"`+totpNow(secret)+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("totp complete: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	// 3) login: password factor -> challenge -> TOTP factor -> session
	rec = do(http.MethodPost, "/admin/login/password", "", `{"email":"`+email+`","password":"wrong"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: want 401, got %d", rec.Code)
	}
	rec = do(http.MethodPost, "/admin/login/password", "", `{"email":"`+email+`","password":"a-strong-passphrase-123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("password login: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	challenge, _ := decode(rec)["challenge_token"].(string)
	rec = do(http.MethodPost, "/admin/login/totp", "", `{"challenge_token":"`+challenge+`","code":"`+totpNow(secret)+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("totp login: want 201, got %d body=%s", rec.Code, rec.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "admin_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatalf("no admin_session cookie issued")
	}

	// 4) the session is attributed to the operator's email principal
	rec = do(http.MethodGet, "/admin/session", "", "", sessionCookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("session: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	sess := decode(rec)
	if sess["auth_method"] != "admin_session" {
		t.Fatalf("auth_method = %v, want admin_session", sess["auth_method"])
	}
	if pid, _ := sess["principal_id"].(string); !strings.HasPrefix(pid, "adm_") {
		t.Fatalf("principal_id = %v, want an adm_ principal", sess["principal_id"])
	}
}
