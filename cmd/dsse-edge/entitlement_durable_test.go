package main

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type entitlementReviewPersister struct {
	raw  []byte
	fail bool
	ctx  context.Context
}

func (p *entitlementReviewPersister) Load() ([]byte, error) {
	return append([]byte(nil), p.raw...), nil
}
func (p *entitlementReviewPersister) Save(raw []byte) error {
	if p.fail {
		return errors.New("save rejected")
	}
	p.raw = append([]byte(nil), raw...)
	return nil
}
func (p *entitlementReviewPersister) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	p.ctx = ctx
	raw, err := edit(p.raw)
	if err != nil {
		return err
	}
	return p.Save(raw)
}

func TestEntitlementDurableSharedFailureAndRestart(t *testing.T) {
	p := &entitlementReviewPersister{}
	a := newEntitlementStore(nil)
	b := newEntitlementStore(nil)
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if err := b.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.SetFeaturesContext(ctx, "one", map[string]bool{featureDLP: true}); err != nil {
		t.Fatal(err)
	}
	if p.ctx != ctx {
		t.Fatal("request context lost")
	}
	if err := b.SetFeaturesContext(ctx, "two", map[string]bool{featureDLP: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if !a.Entitled("one", featureDLP) || !a.Entitled("two", featureDLP) {
		t.Fatal("peer grant lost")
	}
	before := string(p.raw)
	p.fail = true
	if err := a.SetFeaturesContext(ctx, "one", map[string]bool{featureDLP: false}); err == nil {
		t.Fatal("save failure acknowledged")
	}
	if !a.Entitled("one", featureDLP) || string(p.raw) != before {
		t.Fatal("failed mutation published")
	}
	p.fail = false
	if err := a.SetFeaturesContext(ctx, "one", map[string]bool{featureDLP: false}); err != nil {
		t.Fatal(err)
	}
	restored := newEntitlementStore(nil)
	if err := restored.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if restored.Entitled("one", featureDLP) || !restored.Entitled("two", featureDLP) {
		t.Fatal("restart differs")
	}
	p.raw = []byte(`{"features":null}`)
	if err := a.RefreshShared(); err == nil {
		t.Fatal("corrupt authority accepted")
	}
}

func TestAdminEntitlementConfirmedSaveFailureAndRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "entitlements.json")
	now := time.Now().UTC()
	tenant := testEvaluator().PolicyBundle.TenantID
	creds := newLocalAdminCredentialStore("DSSE")
	seedActiveAdminAccount(t, creds, "review@example.test", tenant, "reviewer", []string{"admin", "super_admin"}, now)
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(principalFromCredential(creds.byEmail["review@example.test"], now))
	auth.UpsertSession(adminSession{ID: "review-session", TenantID: tenant, AdminPrincipalID: "reviewer", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "review-csrf"}})
	writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, LocalCredentials: creds, OperatorTenantID: tenant, EntitlementStorePath: path}
	handler := newServerWithConfig(cfg)
	request := func(method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/admin/entitlements", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "admin_session", Value: "review-session"})
		req.Header.Set("X-CSRF-Token", "review-csrf")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if r := request("PUT", `{"features":{"dlp":false}}`); r.Code != 200 {
		t.Fatalf("save %d: %s", r.Code, r.Body.String())
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Fatalf("200 before persistence: %v", err)
	}
	handler = newServerWithConfig(cfg)
	if r := request("GET", ""); !strings.Contains(r.Body.String(), `"dlp":false`) {
		t.Fatalf("restart: %s", r.Body.String())
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if r := request("PUT", `{"features":{"dlp":true}}`); r.Code != 500 {
		t.Fatalf("save failure %d: %s", r.Code, r.Body.String())
	}
	if r := request("GET", ""); !strings.Contains(r.Body.String(), `"dlp":false`) {
		t.Fatal("failed grant published")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if r := request("PUT", `{"features":{"dlp":true}}`); r.Code != 200 {
		t.Fatalf("retry %d", r.Code)
	}
	handler = newServerWithConfig(cfg)
	if r := request("GET", ""); !strings.Contains(r.Body.String(), `"dlp":true`) {
		t.Fatal("retry missing after restart")
	}
}

func TestEntitlementInvalidRestoreKeepsWriter(t *testing.T) {
	good := &entitlementReviewPersister{raw: []byte(`{"features":{"one":{"dlp":true}}}`)}
	s := newEntitlementStore(nil)
	if err := s.SetPersister(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`null`, `{}`, `{"features":null}`} {
		broken := &entitlementReviewPersister{raw: []byte(bad)}
		if err := s.SetPersister(broken); err == nil {
			t.Fatalf("accepted %q", bad)
		}
		if !s.Entitled("one", featureDLP) {
			t.Fatal("failed restore changed live")
		}
	}
	if err := s.SetFeaturesContext(context.Background(), "two", map[string]bool{featureDLP: true}); err != nil {
		t.Fatal(err)
	}
	restored := newEntitlementStore(nil)
	if err := restored.SetPersister(good); err != nil {
		t.Fatal(err)
	}
	if !restored.Entitled("two", featureDLP) {
		t.Fatal("failed restore replaced writer")
	}
}
