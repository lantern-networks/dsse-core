package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestAgentReleaseReadsShareVerifiedPublicationScope(t *testing.T) {
	root := t.TempDir()
	w, err := logs.NewWriter(filepath.Join(root, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	signer := updateSigner(t)
	keys := []string{signer.PublicKeyHex()}
	store := newPublishedAgentUpdateStore()
	path := filepath.Join(root, "releases.json")
	if err := store.LoadFrom(path, "tenant_lab_001"); err != nil {
		t.Fatal(err)
	}
	ratchet := newAgentUpdateSignRatchet(root)
	versions := map[string]string{"deployment": "0.3.1", "tenant_lab_001": "0.2.8", "tenant_other": "9.9.9"}
	for scope, version := range versions {
		_, envelope := signedUpdate(t, signer, version, time.Now())
		if _, _, _, err := store.Publish(scope, envelope, keys, time.Now(), nil); err != nil {
			t.Fatal(err)
		}
		if err := ratchet.Record(scope, "windows", "amd64", version); err != nil {
			t.Fatal(err)
		}
	}
	auth := newAdminAuthStore()
	for _, role := range []string{"operator", "tenant", "other", "readless"} {
		tenant, roles, scopes := "tenant_lab_001", []string{"admin"}, []string{"*"}
		if role == "operator" {
			roles = append(roles, "super_admin")
		}
		if role == "other" {
			tenant = "tenant_other"
		}
		if role == "readless" {
			scopes = []string{"admin.endpoints.read"}
		}
		auth.UpsertPrincipal(adminPrincipal{ID: role, TenantID: tenant, Roles: roles, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: role, TokenHash: adminTokenHash(role + "-read-fixture"), TenantID: tenant, CreatedByAdminPrincipalID: role, Roles: roles, Scopes: scopes, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	out := &recordingAdminAuditOutboxDeadReader{}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w, AdminAuth: auth, OperatorTenantID: "tenant_lab_001", PublishedAgentUpdateStore: store, AgentUpdatePins: keys, AgentUpdateSigner: signer, AgentUpdateSignFloor: ratchet, AdminAuditOutbox: out})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ role, header, scope string }{{"operator", "", "deployment"}, {"operator", "tenant_lab_001", "tenant_lab_001"}, {"operator", "tenant_other", "tenant_other"}, {"tenant", "", "tenant_lab_001"}, {"other", "", "tenant_other"}} {
		for _, route := range []string{"agent-updates", "agent-update-sign-floor"} {
			for _, pin := range []string{"omitted", tc.scope, "", "wrong"} {
				t.Run(tc.role+"/"+tc.header+"/"+route+"/"+pin, func(t *testing.T) {
					path := "/admin/" + route
					if pin != "omitted" {
						path += "?expected_tenant_id=" + url.QueryEscape(pin)
					}
					r := httptest.NewRequest("GET", path, nil)
					r.Header.Set("Authorization", "Bearer "+tc.role+"-read-fixture")
					r.Header.Set("X-Operate-Tenant", tc.header)
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, r)
					if pin != "omitted" && pin != tc.scope {
						if rec.Code != 409 || strings.Contains(rec.Body.String(), "floors") || strings.Contains(rec.Body.String(), "envelopes") {
							t.Fatalf("scope mismatch disclosed catalogue %d %s", rec.Code, rec.Body)
						}
						return
					}
					var b map[string]any
					if json.Unmarshal(rec.Body.Bytes(), &b) != nil || rec.Code != 200 || b["tenant_id"] != tc.scope {
						t.Fatalf("wrong scope %d %s", rec.Code, rec.Body)
					}
					if route == "agent-update-sign-floor" {
						if !reflect.DeepEqual(b["floors"], map[string]any{"windows/amd64": versions[tc.scope]}) || b["signing_public_key"] != signer.PublicKeyHex() {
							t.Fatal("wrong signing floor", b)
						}
					} else {
						if b["schema_version"] != "admin_agent_updates.v1" {
							t.Fatal("catalogue schema", b)
						}
					}
				})
			}
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || w.AuditHealth().Attempts != 0 || len(out.insertedAudits) != 0 {
		t.Fatal("reads mutated catalogue or created change audits")
	}
	for _, route := range []string{"agent-updates", "agent-update-sign-floor"} {
		for _, tc := range []struct {
			token, header string
			status        int
		}{{"", "", 401}, {"readless-read-fixture", "", 403}, {"tenant-read-fixture", "tenant_other", 403}} {
			r := httptest.NewRequest("GET", "/admin/"+route+"?expected_tenant_id=wrong", nil)
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			r.Header.Set("X-Operate-Tenant", tc.header)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != tc.status {
				t.Fatalf("auth priority %s %d %s", route, rec.Code, rec.Body)
			}
		}
	}
}

func TestAgentReleaseReadContextIncludesEmptyLegacyScope(t *testing.T) {
	for _, scope := range []string{"", "deployment"} {
		for _, query := range []string{"", "?expected_tenant_id=", "?expected_tenant_id=deployment", "?expected_tenant_id=other"} {
			r := httptest.NewRequest("GET", "/admin/agent-updates"+query, nil)
			w := httptest.NewRecorder()
			want := !r.URL.Query().Has("expected_tenant_id") || r.URL.Query().Get("expected_tenant_id") == scope
			if got := agentUpdateReadContextMatches(w, r, scope); got != want || (!want && w.Code != 409) {
				t.Fatalf("scope %q query %q: %v / %d", scope, query, got, w.Code)
			}
		}
	}
}
