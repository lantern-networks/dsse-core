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

func TestAgentReleaseWritesPinScopeAndConfirmPackage(t *testing.T) {
	oldOp, oldLegacy := operatorTenantConfigured(), operatorTenantlessMode.Load()
	defer func() { operatorTenantAuthority.Store(oldOp); operatorTenantlessMode.Store(oldLegacy) }()
	for _, selected := range []string{"", "tenant_lab_001", "tenant_other"} {
		t.Run("selected/"+selected, func(t *testing.T) {
			root := t.TempDir()
			writer, err := logs.NewWriter(filepath.Join(root, "logs"))
			if err != nil {
				t.Fatal(err)
			}
			signer := updateSigner(t)
			keys := []string{signer.PublicKeyHex()}
			store := newPublishedAgentUpdateStore()
			if err := store.LoadFrom(filepath.Join(root, "releases.json"), "tenant_lab_001"); err != nil {
				t.Fatal(err)
			}
			ratchet := newAgentUpdateSignRatchet(root)
			if err := ratchet.Load(); err != nil {
				t.Fatal(err)
			}
			scope := selected
			if scope == "" {
				scope = "deployment"
			}
			m, env := signedUpdate(t, signer, "0.3.2", time.Now())
			if _, _, _, err := store.Publish(scope, env, keys, time.Now(), nil); err != nil {
				t.Fatal(err)
			}
			auth := newAdminAuthStore()
			for _, who := range []string{"operator", "read-only"} {
				scopes := []string{"*"}
				if who == "read-only" {
					scopes = []string{"admin.agents.read"}
				}
				auth.UpsertPrincipal(adminPrincipal{ID: who, TenantID: "tenant_lab_001", Roles: []string{"admin", "super_admin"}, Status: "active"})
				auth.UpsertAPIToken(adminAPIToken{ID: who, TokenHash: adminTokenHash(who + "-publication-test"), TenantID: "tenant_lab_001", CreatedByAdminPrincipalID: who, Roles: []string{"admin", "super_admin"}, Scopes: scopes, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
			}
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "tenant_lab_001", PublishedAgentUpdateStore: store, AgentUpdatePins: keys, AgentUpdateSigner: signer, AgentUpdateSignFloor: ratchet, AgentUpdateArtifactDir: filepath.Join(root, "artifacts")})
			snapshot := func() map[string]string {
				out := map[string]string{}
				if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if !d.IsDir() {
						b, e := os.ReadFile(path)
						if e != nil {
							return e
						}
						out[strings.TrimPrefix(path, root)] = string(b)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				return out
			}
			request := func(method, path, who string, b []byte) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, path, bytes.NewReader(b))
				if who != "" {
					r.Header.Set("Authorization", "Bearer "+who+"-publication-test")
				}
				if selected != "" {
					r.Header.Set("X-Operate-Tenant", selected)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, r)
				return rec
			}
			envelope, _ := json.Marshal(env)
			manifest, _ := json.Marshal(m)
			for _, op := range []struct {
				method, path string
				body         []byte
			}{{"PUT", "/admin/agent-updates", envelope}, {"POST", "/admin/agent-updates", manifest}, {"PUT", "/admin/agent-update-artifact?platform=windows&arch=amd64", artifactBytesFor("0.3.2")}} {
				join := "?"
				if strings.Contains(op.path, "?") {
					join = "&"
				}
				for _, pin := range []string{"", "wrong", url.QueryEscape(scope) + "&expected_tenant_id=wrong"} {
					before := snapshot()
					pending := store.PendingFor(scope)
					active := store.ForTenant(scope)
					floors := ratchet.FloorsForTenant(scope)
					rec := request(op.method, op.path+join+"expected_tenant_id="+pin, "operator", op.body)
					if rec.Code != 409 {
						t.Fatalf("%s %s pin %q got %d %s", op.method, op.path, pin, rec.Code, rec.Body)
					}
					after := snapshot()
					delete(before, "/logs/audit.log.jsonl")
					delete(after, "/logs/audit.log.jsonl")
					if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(pending, store.PendingFor(scope)) || !reflect.DeepEqual(active, store.ForTenant(scope)) || !reflect.DeepEqual(floors, ratchet.FloorsForTenant(scope)) {
						t.Fatal("refused context changed release state")
					}
				}
				// Existing clients may omit the pin. New clients explicitly bind the same scope.
				for _, query := range []string{"", join + "expected_tenant_id=" + url.QueryEscape(scope)} {
					rec := request(op.method, op.path+query, "operator", op.body)
					if rec.Code != 200 {
						t.Fatalf("valid %s %s %d %s", op.method, op.path, rec.Code, rec.Body)
					}
					var body map[string]any
					if json.Unmarshal(rec.Body.Bytes(), &body) != nil || body["tenant_id"] != scope || body["schema_version"] != "admin_agent_updates.v1" {
						t.Fatalf("scope ack %s", rec.Body)
					}
					hash, ok := body["manifest_sha256"].(string)
					if !ok || len(hash) != 64 {
						t.Fatalf("manifest ack %s", rec.Body)
					}
					key := "published"
					if strings.Contains(op.path, "artifact") {
						key = "stored"
					}
					got, ok := body[key].(map[string]any)
					if !ok || got["platform"] != m.Platform || got["arch"] != m.Arch || got["version"] != m.Version || got["artifact_sha256"] != m.ArtifactSHA256 {
						t.Fatalf("package ack %s", rec.Body)
					}
					if key == "stored" {
						if got["bytes"] != float64(m.ArtifactSize) || body["active"] != true {
							t.Fatalf("upload ack %s", rec.Body)
						}
					} else {
						if got["artifact_size"] != float64(m.ArtifactSize) || (body["state"] != "active" && body["state"] != "pending") {
							t.Fatalf("publish ack %s", rec.Body)
						}
					}
				}
			}
			// Upload a stale or ambiguous manifest pin: bytes and active/pending state stay intact.
			for _, pin := range []string{"", "wrong", env.PayloadSHA256 + "&expected_manifest_sha256=wrong"} {
				before := snapshot()
				rec := request("PUT", "/admin/agent-update-artifact?platform=windows&arch=amd64&expected_tenant_id="+url.QueryEscape(scope)+"&expected_manifest_sha256="+pin, "operator", artifactBytesFor("0.3.2"))
				if rec.Code != 409 {
					t.Fatalf("stale manifest %d %s", rec.Code, rec.Body)
				}
				after := snapshot()
				delete(before, "/logs/audit.log.jsonl")
				delete(after, "/logs/audit.log.jsonl")
				if !reflect.DeepEqual(before, after) {
					t.Fatal("stale manifest changed saved state")
				}
			}
			current := store.ForTenant(scope)["windows/amd64"]
			rec := request("PUT", "/admin/agent-update-artifact?platform=windows&arch=amd64&expected_tenant_id="+url.QueryEscape(scope)+"&expected_manifest_sha256="+current.PayloadSHA256, "operator", artifactBytesFor("0.3.2"))
			if rec.Code != 200 {
				t.Fatalf("matching manifest %d %s", rec.Code, rec.Body)
			}
			for _, who := range []string{"", "read-only"} {
				for _, method := range []string{"PUT", "POST"} {
					rec := request(method, "/admin/agent-updates?expected_tenant_id=wrong", who, envelope)
					want := 401
					if who != "" {
						want = 403
					}
					if rec.Code != want {
						t.Fatalf("authentication precedence %s %d %s", who, rec.Code, rec.Body)
					}
				}
			}
		})
	}
}
