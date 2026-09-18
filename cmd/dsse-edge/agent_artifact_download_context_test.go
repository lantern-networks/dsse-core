package main

import (
	"bytes"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestAgentArtifactDownloadKeepsTenantDefaultAndPinsPublication(t *testing.T) {
	oldOp, oldLegacy := operatorTenantConfigured(), operatorTenantlessMode.Load()
	defer func() { operatorTenantAuthority.Store(oldOp); operatorTenantlessMode.Store(oldLegacy) }()
	root := t.TempDir()
	signer := updateSigner(t)
	keys := []string{signer.PublicKeyHex()}
	store := newPublishedAgentUpdateStore()
	catalog := filepath.Join(root, "releases.json")
	if err := store.LoadFrom(catalog, "tenant_lab_001"); err != nil {
		t.Fatal(err)
	}
	artifacts := filepath.Join(root, "artifacts")
	for scope, version := range map[string]string{"deployment": "0.3.1", "tenant_lab_001": "0.2.8", "tenant_other": "0.4.0"} {
		m, env := signedUpdate(t, signer, version, time.Now())
		path := artifactStorePath(artifacts, scope, m.Platform, m.Arch, m.Version)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, artifactBytesFor(version), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := store.Publish(scope, env, keys, time.Now(), func(agentupdate.Manifest) bool { return true }); err != nil {
			t.Fatal(err)
		}
	}
	_, pending := signedUpdate(t, signer, "0.3.2", time.Now())
	if _, _, _, err := store.Publish("deployment", pending, keys, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(filepath.Join(root, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	for _, who := range []string{"operator", "tenant", "other", "fallback", "readless"} {
		tenant, roles, scopes := "tenant_lab_001", []string{"admin"}, []string{"*"}
		if who == "operator" {
			roles = append(roles, "super_admin")
		}
		if who == "other" {
			tenant = "tenant_other"
		}
		if who == "fallback" {
			tenant = "tenant_fallback"
		}
		if who == "readless" {
			scopes = []string{"admin.endpoints.read"}
		}
		auth.UpsertPrincipal(adminPrincipal{ID: who, TenantID: tenant, Roles: roles, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: who, TokenHash: adminTokenHash(who + "-artifact-test"), TenantID: tenant, CreatedByAdminPrincipalID: who, Roles: roles, Scopes: scopes, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "tenant_lab_001", PublishedAgentUpdateStore: store, AgentUpdatePins: keys, AgentUpdateArtifactDir: artifacts})
	request := func(who, selection, query, rangeHeader string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/admin/agent-update-artifact?platform=windows&arch=amd64"+query, nil)
		if who != "" {
			r.Header.Set("Authorization", "Bearer "+who+"-artifact-test")
		}
		if selection != "" {
			r.Header.Set("X-Operate-Tenant", selection)
		}
		if rangeHeader != "" {
			r.Header.Set("Range", rangeHeader)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	before, err := os.ReadFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ who, selection, query, scope, version string }{
		{"operator", "", "", "tenant_lab_001", "0.2.8"}, {"operator", "", "&artifact_scope=tenant", "tenant_lab_001", "0.2.8"},
		{"operator", "", "&artifact_scope=publication", "deployment", "0.3.1"}, {"operator", "tenant_lab_001", "&artifact_scope=publication", "tenant_lab_001", "0.2.8"},
		{"operator", "tenant_other", "&artifact_scope=publication", "tenant_other", "0.4.0"}, {"tenant", "", "&artifact_scope=publication", "tenant_lab_001", "0.2.8"},
		{"other", "", "&artifact_scope=publication", "tenant_other", "0.4.0"}, {"fallback", "", "&artifact_scope=publication", "tenant_fallback", "0.3.1"},
	} {
		t.Run(tc.who+tc.selection+tc.query, func(t *testing.T) {
			env := store.ForTenant(tc.scope)["windows/amd64"]
			for _, pins := range []string{"", "&expected_tenant_id=" + url.QueryEscape(tc.scope) + "&expected_manifest_sha256=" + env.PayloadSHA256} {
				w := request(tc.who, tc.selection, tc.query+pins, "")
				if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), artifactBytesFor(tc.version)) {
					t.Fatalf("download %d %s", w.Code, w.Body)
				}
				if w.Header().Get(agentupdate.ArtifactVersionHeader) != tc.version || w.Header().Get("X-Dsse-Agent-Update-Scope") != tc.scope || w.Header().Get("X-Dsse-Agent-Update-Manifest-SHA256") != env.PayloadSHA256 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("unbound response headers", w.Header())
				}
			}
			for _, pins := range []string{"&expected_tenant_id=", "&expected_tenant_id=wrong", "&expected_tenant_id=" + tc.scope + "&expected_tenant_id=" + tc.scope, "&expected_manifest_sha256=", "&expected_manifest_sha256=wrong", "&expected_manifest_sha256=" + pending.PayloadSHA256, "&expected_manifest_sha256=" + env.PayloadSHA256 + "&expected_manifest_sha256=" + env.PayloadSHA256} {
				w := request(tc.who, tc.selection, tc.query+pins, "")
				if w.Code != 409 {
					t.Fatalf("bad pin %s got %d %s", pins, w.Code, w.Body)
				}
				if w.Header().Get(agentupdate.ArtifactVersionHeader) != "" {
					t.Fatal("refusal disclosed artifact headers")
				}
			}
		})
	}
	for _, query := range []string{"&artifact_scope=", "&artifact_scope=deployment", "&artifact_scope=publication&artifact_scope=publication"} {
		if w := request("operator", "", query, ""); w.Code != 400 {
			t.Fatalf("scope %s got %d", query, w.Code)
		}
	}
	w := request("operator", "", "", "bytes=0-2")
	if w.Code != 206 || !bytes.Equal(w.Body.Bytes(), artifactBytesFor("0.2.8")[:3]) {
		t.Fatal("legacy Range changed", w.Code)
	}
	after, err := os.ReadFile(catalog)
	if err != nil || !bytes.Equal(before, after) || writer.AuditHealth().Attempts != 0 {
		t.Fatal("read mutated catalogue or wrote an operation audit")
	}
	for _, tc := range []struct {
		who, selection string
		status         int
	}{{"", "", 401}, {"readless", "", 403}, {"tenant", "tenant_other", 403}} {
		w := request(tc.who, tc.selection, "&artifact_scope=bad&expected_tenant_id=wrong", "")
		if w.Code != tc.status {
			t.Fatalf("auth priority %d %s", w.Code, w.Body)
		}
	}
	if w := request("other", "", "&artifact_scope=publication&expected_tenant_id=deployment", ""); w.Code != 409 {
		t.Fatal("customer pin selected deployment", w.Code)
	}
	if w := request("operator", "", "&artifact_scope=publication&expected_manifest_sha256="+strings.ToUpper(store.ForTenant("deployment")["windows/amd64"].PayloadSHA256), ""); w.Code != 200 {
		t.Fatal("hash case compatibility", w.Code)
	}
}
