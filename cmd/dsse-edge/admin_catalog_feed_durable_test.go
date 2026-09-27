package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/catalogfeed"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policyrule"
	"github.com/lantern-networks/dsse-core/signedconfig"
)

func TestAdminCatalogFeedSaveFailureRetryAndOverride(t *testing.T) {
	oldOperator := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(oldOperator) })
	for _, operation := range []string{"apply", "rollback"} {
		t.Run(operation, func(t *testing.T) {
			pub, priv, e := ed25519.GenerateKey(nil)
			if e != nil {
				t.Fatal(e)
			}
			key := "ed25519-public:test"
			now := time.Now().UTC()
			keys := map[string]ed25519.PublicKey{key: pub}
			envelope := func(version int, host string) []byte {
				t.Helper()
				payload, e := json.Marshal(knownbypass.CatalogDocument{Version: version, Entries: []knownbypass.Group{{ID: "feed_service", Patterns: []string{host}}}})
				if e != nil {
					t.Fatal(e)
				}
				sum, e := signedconfig.PayloadChecksum(payload)
				if e != nil {
					t.Fatal(e)
				}
				env, e := signedconfig.Sign(signedconfig.Envelope{Type: catalogfeed.FeedType, Version: host, Payload: payload, Checksum: sum, SigningKeyID: key, Status: "active", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}, priv)
				if e != nil {
					t.Fatal(e)
				}
				b, e := json.Marshal(env)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			one, two := envelope(101, "alpha.example"), envelope(102, "beta.example")
			dir := t.TempDir()
			path := filepath.Join(dir, "feed.json")
			feed := catalogfeed.NewStore(keys)
			if e := feed.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			if _, e := feed.Apply(one, now); e != nil {
				t.Fatal(e)
			}
			if operation == "rollback" {
				if _, e := feed.Apply(two, now); e != nil {
					t.Fatal(e)
				}
			}
			tenant := testEvaluator().PolicyBundle.TenantID
			auth := newAdminAuthStore()
			for _, id := range []string{tenant, "foreign"} {
				auth.UpsertPrincipal(adminPrincipal{ID: id, TenantID: id, Roles: []string{"admin", "super_admin"}, Status: "active"})
				auth.UpsertSession(adminSession{ID: id + "-session", TenantID: id, AdminPrincipalID: id, Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "feed-csrf"}})
			}
			writer, e := logs.NewWriter(filepath.Join(dir, "logs"))
			if e != nil {
				t.Fatal(e)
			}
			defer writer.Close()
			overrides := knownbypass.NewOverrideStore()
			if e := overrides.SetStatePath(filepath.Join(dir, "overrides.json")); e != nil {
				t.Fatal(e)
			}
			engine := edgeplane.NewNetworkExtensionLabTLSInterceptionMatchOnly([]string{"*"})
			apply := newTenantInspectionApplier(engine, inspectionposture.NewStore(), policyrule.NewStore(), assetcatalog.NewStore(), overrides, func() []knownbypass.Group { return feed.EffectiveCatalog().Entries }, []string{"*"}, nil)
			apply("")
			applies := 0
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, Writer: writer, OperatorTenantID: tenant, CatalogFeed: feed, CatalogOverrides: overrides, NetworkExtensionLabTLS: engine, ApplyMaterializedCertPinBypass: func(tenant string) { applies++; apply(tenant) }})
			applies = 0
			call := func(id, method, path string, body []byte) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, path, bytes.NewReader(body))
				r.AddCookie(&http.Cookie{Name: "admin_session", Value: id + "-session"})
				r.Header.Set("X-CSRF-Token", "feed-csrf")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			status := func() string { return call(tenant, "GET", "/admin/predefined-catalog/feed", nil).Body.String() }
			old := status()
			saved, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			route, body := "/admin/predefined-catalog/feed", two
			oldHost, newHost := "alpha.example", "beta.example"
			if operation == "rollback" {
				route += "/rollback"
				body = []byte(`{"catalog_version":101}`)
				oldHost, newHost = newHost, oldHost
			}
			match := func(id, host string) bool {
				return engine.Matches(edgeplane.NetworkExtensionRuntimeCopyTCPRoute{TenantID: id, Host: host, Port: 443})
			}
			if e := os.Rename(path, path+".saved"); e != nil {
				t.Fatal(e)
			}
			if e := os.Mkdir(path, 0700); e != nil {
				t.Fatal(e)
			}
			w := call(tenant, "POST", route, body)
			if w.Code != 500 || strings.Contains(w.Body.String(), dir) {
				t.Fatalf("save failure %d %s", w.Code, w.Body)
			}
			if status() != old || applies != 0 || match(tenant, oldHost) || !match(tenant, newHost) {
				t.Fatal("failed write changed view or matcher")
			}
			if e := os.Remove(path); e != nil {
				t.Fatal(e)
			}
			if e := os.Rename(path+".saved", path); e != nil {
				t.Fatal(e)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(saved, after) {
				t.Fatal("file changed")
			}
			if w := call(tenant, "POST", route, body); w.Code != 200 {
				t.Fatalf("retry %d %s", w.Code, w.Body)
			}
			if applies != 1 || match(tenant, newHost) || match("foreign", newHost) || !match(tenant, oldHost) {
				t.Fatal("successful feed did not rebuild all tenants")
			}
			if w := call(tenant, "POST", "/admin/predefined-catalog/feed", []byte(`{}`)); w.Code != 400 {
				t.Fatal("validation classification", w.Code)
			}
			for _, r := range []string{"/admin/predefined-catalog/feed", "/admin/predefined-catalog/feed/rollback"} {
				if w := call("foreign", "POST", r, body); w.Code != 403 {
					t.Fatal("tenant changed deployment feed", w.Code)
				}
			}
			if w := call(tenant, "POST", "/admin/predefined-catalog/overrides", []byte(`{"entry_id":"feed_service","mode":"disabled"}`)); w.Code != 200 {
				t.Fatalf("feed-only override %d %s", w.Code, w.Body)
			}
			if applies != 2 || !match(tenant, newHost) || match("foreign", newHost) {
				t.Fatal("override did not stay in its tenant")
			}
			restored := catalogfeed.NewStore(keys)
			if e := restored.SetStatePath(path); e != nil {
				t.Fatal(e)
			}
			if restored.EffectiveCatalog().Version != feed.EffectiveCatalog().Version {
				t.Fatal("restart")
			}
			rows, e := writer.ReadJSONL("audit.log.jsonl")
			if e != nil {
				t.Fatal(e)
			}
			if len(rows) != 6 {
				t.Fatal("audit count", len(rows))
			}
			for i, a := range rows {
				result := "error"
				if i == 1 || i == 5 {
					result = "success"
				}
				id := tenant
				if i == 3 || i == 4 {
					id = "foreign"
				}
				if a["result"] != result || a["tenant_id"] != id || a["actor_user_id"] != id || a["action"] != "POST" {
					t.Fatalf("audit %d: %+v", i, a)
				}
			}
			raw, e := json.Marshal(rows)
			if e != nil {
				t.Fatal(e)
			}
			for _, secret := range []string{dir, "feed-csrf", tenant + "-session", "foreign-session"} {
				if bytes.Contains(raw, []byte(secret)) {
					t.Fatal("private audit value", secret)
				}
			}
		})
	}
}
