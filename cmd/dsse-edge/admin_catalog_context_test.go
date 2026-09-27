package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/catalogfeed"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/signedconfig"
)

func TestCatalogContextGuardsEveryRouteAndPreservesLegacyClients(t *testing.T) {
	oldOperator := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(oldOperator) })
	dir := t.TempDir()
	now := time.Now().UTC()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	key := "ed25519-public:fixture"
	feed := catalogfeed.NewStore(map[string]ed25519.PublicKey{key: priv.Public().(ed25519.PublicKey)})
	feedPath := filepath.Join(dir, "feed.json")
	if err := feed.SetStatePath(feedPath); err != nil {
		t.Fatal(err)
	}
	envelope := func(version int) []byte {
		t.Helper()
		payload, _ := json.Marshal(knownbypass.CatalogDocument{Version: version, Entries: []knownbypass.Group{{ID: "service", Patterns: []string{"service.example"}}}})
		sum, _ := signedconfig.PayloadChecksum(payload)
		env, err := signedconfig.Sign(signedconfig.Envelope{Type: catalogfeed.FeedType, Version: "fixture", Payload: payload, Checksum: sum, SigningKeyID: key, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}, priv)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(env)
		return raw
	}
	if _, err := feed.Apply(envelope(101), now); err != nil {
		t.Fatal(err)
	}
	overrides := knownbypass.NewOverrideStore()
	op := filepath.Join(dir, "overrides.json")
	if err := overrides.SetStatePath(op); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"operator", "other"} {
		if _, err := overrides.SetFromCatalog(tenant, knownbypass.Override{EntryID: "service", Mode: "disabled"}, feed.EffectiveCatalog().Entries, now); err != nil {
			t.Fatal(err)
		}
	}
	auth := newAdminAuthStore()
	for _, tenant := range []string{"operator", "other"} {
		roles := []string{"admin", "super_admin"}
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: roles, Status: "active"})
		auth.UpsertSession(adminSession{ID: tenant + "-session", TenantID: tenant, AdminPrincipalID: tenant, Roles: roles, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "fixture-csrf"}})
	}
	writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	applies := 0
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, Writer: writer, OperatorTenantID: "operator", CatalogFeed: feed, CatalogOverrides: overrides, ApplyMaterializedCertPinBypass: func(string) { applies++ }})
	applies = 0
	call := func(tenant, method, path string, body []byte, want int) map[string]any {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: tenant + "-session"})
		r.Header.Set("X-CSRF-Token", "fixture-csrf")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s got %d: %s", method, path, w.Code, w.Body)
		}
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	read := func(path string) []byte {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	beforeFeed, beforeOverrides := read(feedPath), read(op)
	routes := []struct {
		method, path, scope string
		body                []byte
	}{
		{"GET", "/admin/predefined-catalog", "tenant", nil},
		{"GET", "/admin/predefined-catalog/feed", "deployment", nil},
		{"POST", "/admin/predefined-catalog/feed", "deployment", envelope(102)},
		{"POST", "/admin/predefined-catalog/feed/rollback", "deployment", []byte(`{"catalog_version":101}`)},
		{"POST", "/admin/predefined-catalog/overrides", "tenant", []byte(`{"entry_id":"service","mode":"force_inspect"}`)},
		{"POST", "/admin/predefined-catalog/overrides/service/clear", "tenant", []byte(`{}`)},
	}
	for _, tenant := range []string{"operator", "other"} {
		for _, route := range routes {
			call(tenant, route.method, route.path+"?scoped=1&expected_tenant_id=wrong", route.body, 409)
		}
	}
	if applies != 0 || !bytes.Equal(beforeFeed, read(feedPath)) || !bytes.Equal(beforeOverrides, read(op)) {
		t.Fatal("context refusal changed persistent or live state")
	}
	for _, route := range routes {
		if route.method == "GET" {
			for _, tenant := range []string{"operator", "other"} {
				legacy := call(tenant, "GET", route.path, nil, 200)
				scoped := call(tenant, "GET", route.path+"?scoped=1&expected_tenant_id="+tenant, nil, 200)
				if scoped["tenant_id"] != tenant || scoped["scope"] != route.scope {
					t.Fatal(scoped)
				}
				a, _ := json.Marshal(legacy)
				b, _ := json.Marshal(scoped["data"])
				if !bytes.Equal(a, b) {
					t.Fatal("legacy payload changed")
				}
			}
		}
	}
	for _, route := range routes[2:4] {
		call("other", route.method, route.path+"?scoped=1&expected_tenant_id=other", route.body, 403)
	}
	if applies != 0 || !bytes.Equal(beforeFeed, read(feedPath)) {
		t.Fatal("tenant administrator changed deployment feed")
	}
	for _, route := range routes[2:] {
		result := call("operator", route.method, route.path+"?scoped=1&expected_tenant_id=operator", route.body, 200)
		if result["tenant_id"] != "operator" || result["scope"] != route.scope {
			t.Fatal(result)
		}
		data := result["data"].(map[string]any)
		if route.scope == "deployment" && data["catalog_version"] == nil {
			t.Fatal("missing feed ack")
		}
		if route.scope == "tenant" && data["entry_id"] != "service" {
			t.Fatal("missing override ack")
		}
	}
	if applies != 4 || len(overrides.List("operator")) != 0 || len(overrides.List("other")) != 1 || feed.Status(now).CatalogVersion != 101 {
		t.Fatal("unexpected post-write state")
	}
	reopened := knownbypass.NewOverrideStore()
	if err := reopened.SetStatePath(op); err != nil {
		t.Fatal(err)
	}
	if len(reopened.List("operator")) != 0 || len(reopened.List("other")) != 1 {
		t.Fatal("restart lost tenant isolation")
	}
	// The old body and response remain accepted when no scoped query is present.
	legacy := call("other", "POST", "/admin/predefined-catalog/overrides", []byte(`{"entry_id":"service","mode":"force_inspect"}`), 200)
	if legacy["entry_id"] != "service" || legacy["data"] != nil {
		t.Fatal("legacy override contract changed")
	}
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	// 8 rejected context writes, 2 rejected feed permissions, 4 scoped successes,
	// and one legacy success. GET responses are not management changes.
	if len(rows) != 15 {
		t.Fatalf("audits=%d", len(rows))
	}
	for i, row := range rows {
		want := "error"
		if i >= 10 {
			want = "success"
		}
		if row["result"] != want || row["actor_user_id"] == nil || row["tenant_id"] == nil || row["action"] != "POST" {
			t.Fatalf("audit %d: %+v", i, row)
		}
	}
}
