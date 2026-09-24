package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policyrule"
)

type catalogRefusalPersister struct {
	data []byte
	fail bool
}

func (p *catalogRefusalPersister) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *catalogRefusalPersister) Save(b []byte) error {
	if p.fail {
		return errors.New("write /private/catalog-secret-path: refused")
	}
	p.data = bytes.Clone(b)
	return nil
}

func TestAdminCatalogOverrideDurabilityAndAudit(t *testing.T) {
	for _, op := range []string{"create", "replace", "clear"} {
		t.Run(op, func(t *testing.T) {
			tenant := testEvaluator().PolicyBundle.TenantID
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "reviewer", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			auth.UpsertSession(adminSession{ID: "catalog-session", TenantID: tenant, AdminPrincipalID: "reviewer", Roles: []string{"admin"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "catalog-csrf"}})
			writer, e := logs.NewWriter(filepath.Join(t.TempDir(), "logs"))
			if e != nil {
				t.Fatal(e)
			}
			defer writer.Close()
			p := &catalogRefusalPersister{}
			s := knownbypass.NewOverrideStore()
			if e := s.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if _, e := s.Set("other", knownbypass.Override{EntryID: "apple_time", Mode: knownbypass.OverrideDisabled}, time.Now()); e != nil {
				t.Fatal(e)
			}
			if op != "create" {
				if _, e := s.Set(tenant, knownbypass.Override{EntryID: "github_asset_cdn", Mode: knownbypass.OverrideForceInspect}, time.Now()); e != nil {
					t.Fatal(e)
				}
			}
			engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
			apply := newTenantInspectionApplier(engine, inspectionposture.NewStore(), policyrule.NewStore(), assetcatalog.NewStore(), s, func() []knownbypass.Group { return knownbypass.Catalog().Entries }, []string{"*"}, nil)
			apply("")
			applies := 0
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, Writer: writer, OperatorTenantID: "operator", CatalogOverrides: s, NetworkExtensionLabTLS: engine, ApplyMaterializedCertPinBypass: func(tenant string) { applies++; apply(tenant) }})
			call := func(method, path, body string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, path, strings.NewReader(body))
				r.AddCookie(&http.Cookie{Name: "admin_session", Value: "catalog-session"})
				r.Header.Set("X-CSRF-Token", "catalog-csrf")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			path := "/admin/predefined-catalog/overrides"
			body := `{"entry_id":"github_asset_cdn","mode":"disabled"}`
			if op == "clear" {
				path += "/github_asset_cdn/clear"
				body = `{}`
			}
			applies = 0 // server construction applies the initial configuration
			before := call("GET", "/admin/predefined-catalog", "").Body.String()
			saved := bytes.Clone(p.data)
			p.fail = true
			w := call("POST", path, body)
			if w.Code != 500 || strings.Contains(w.Body.String(), "/private/") {
				t.Fatalf("storage error %d %s", w.Code, w.Body)
			}
			if before != call("GET", "/admin/predefined-catalog", "").Body.String() || applies != 0 || !bytes.Equal(saved, p.data) {
				t.Fatal("failed save published a change")
			}
			match := func(tenant string) bool {
				return engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: tenant, Host: "github.githubassets.com", Port: 443})
			}
			if match(tenant) != (op != "create") || match("other") {
				t.Fatal("failed save changed interception")
			}
			p.fail = false
			if w := call("POST", path, body); w.Code != 200 {
				t.Fatalf("retry %d %s", w.Code, w.Body)
			}
			if applies != 1 || match(tenant) != (op != "clear") || match("other") {
				t.Fatal("retry not applied only to owner")
			}
			reopened := knownbypass.NewOverrideStore()
			if e := reopened.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if (len(reopened.List(tenant)) != 0) != (op != "clear") || len(reopened.List("other")) != 1 {
				t.Fatal("restart/other tenant")
			}
			if w := call("POST", "/admin/predefined-catalog/overrides", `{"entry_id":"github_asset_cdn","mode":"invalid"}`); w.Code != 400 {
				t.Fatal("validation misclassified", w.Code)
			}
			if applies != 1 {
				t.Fatal("invalid input invoked apply")
			}
			rows, e := writer.ReadJSONL("audit.log.jsonl")
			if e != nil {
				t.Fatal(e)
			}
			if len(rows) != 3 {
				t.Fatal("audit count", len(rows))
			}
			for i, a := range rows {
				result := "error"
				if i == 1 {
					result = "success"
				}
				if a["result"] != result || a["actor_user_id"] != "reviewer" || a["tenant_id"] != tenant || a["action"] != "POST" {
					t.Fatalf("audit %d: %+v", i, a)
				}
				if i < 2 && a["target_id"] != path {
					t.Fatal("wrong target")
				}
			}

			raw, e := json.Marshal(rows)
			if e != nil {
				t.Fatal(e)
			}
			for _, secret := range []string{"/private/catalog-secret-path", "catalog-session", "catalog-csrf"} {
				if bytes.Contains(raw, []byte(secret)) {
					t.Fatal("private value in audit", secret)
				}
			}
		})
	}
}

func TestCatalogOverrideErasureFailureRemainsCounted(t *testing.T) {
	p := &catalogRefusalPersister{}
	s := knownbypass.NewOverrideStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	for _, tenant := range []string{"own", "other"} {
		if _, e := s.Set(tenant, knownbypass.Override{EntryID: "apple_time", Mode: knownbypass.OverrideDisabled}, time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	extra := adminTenantExtraStores{CatalogOverrides: s}
	p.fail = true
	result := adminTenantPurgeResult{TenantID: "own"}
	extra.erase(&result)
	if len(result.Failures) != 1 || len(result.Erased) != 0 || s.CountForTenant("own") != 1 {
		t.Fatal("failed erasure reported complete", result)
	}
	p.fail = false
	result = adminTenantPurgeResult{TenantID: "own"}
	extra.erase(&result)
	if len(result.Failures) != 0 || len(result.Erased) != 1 || result.Erased[0].Count != 1 || s.CountForTenant("own") != 0 || s.CountForTenant("other") != 1 {
		t.Fatal("retry/tenant boundary", result)
	}
}
