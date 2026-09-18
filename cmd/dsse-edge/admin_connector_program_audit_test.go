package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

func TestConnectorPublicationAudits(t *testing.T) {
	for _, mode := range []string{"session", "token", "selected-tenant"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "programs")
			now := time.Now().UTC()
			owner := "tenant_lab_001"
			target := owner
			if mode == "selected-tenant" {
				target = "tenant_other"
			}
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "publisher", TenantID: owner, Email: "publisher@example.test", Roles: []string{"admin", "super_admin"}, Status: "active"})
			auth.UpsertSession(adminSession{ID: "publication-session", TenantID: owner, AdminPrincipalID: "publisher", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "publication-csrf"}})
			token := "publication-test-private-token"
			auth.UpsertAPIToken(adminAPIToken{ID: "publication-api-token", TenantID: owner, TokenHash: adminTokenHash(token), CreatedByAdminPrincipalID: "publisher", Roles: []string{"admin", "super_admin"}, Scopes: []string{"*"}, Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
			writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
			if err != nil {
				t.Fatal(err)
			}
			outbox := &recordingAdminAuditOutboxDeadReader{}
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, OperatorTenantID: owner, ConnectorProgramDir: root, Writer: writer, AdminAuditOutbox: outbox})
			body := "private-program-content"
			digest := sha256Of([]byte(body))
			request := func(method, path, declared, version string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(method, path, strings.NewReader(body))
				if mode == "token" {
					req.Header.Set("Authorization", "Bearer "+token)
				} else {
					req.AddCookie(&http.Cookie{Name: "admin_session", Value: "publication-session"})
					req.Header.Set("X-CSRF-Token", "publication-csrf")
				}
				if target != owner {
					req.Header.Set("X-Operate-Tenant", target)
				}
				req.Header.Set("X-Actor-User-ID", "forged-actor")
				req.Header.Set("X-Artifact-SHA256", declared)
				req.Header.Set("X-Artifact-Version", version)
				req.Header.Set("X-Artifact-Filename", "program.tar.gz")
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, req)
				return rr
			}
			path := "/admin/connector-program?platform=linux&arch=amd64"
			for _, version := range []string{"build-a", "build-b"} {
				r := request("PUT", path, digest, version)
				if r.Code != 200 {
					t.Fatalf("publish %d %s", r.Code, r.Body.String())
				}
			}
			domainCount := func() int {
				n := 0
				for _, a := range readTransportAudits(t, writer) {
					if a.EventType == "admin_connector_program_published" {
						n++
					}
				}
				return n
			}
			if domainCount() != 2 {
				t.Fatal("missing publication audit")
			}
			index := 0
			for _, a := range readTransportAudits(t, writer) {
				raw, _ := json.Marshal(a)
				for _, secret := range []string{body, token, "publication-csrf", "forged-actor", root} {
					if strings.Contains(string(raw), secret) {
						t.Fatal("private request material entered audit")
					}
				}
				if a.EventType != "admin_connector_program_published" {
					continue
				}
				if a.TenantID != target || stringPtrValue(a.ActorUserID) != "publisher" || stringPtrValue(a.TargetID) != "linux/amd64" || stringPtrValue(a.Result) != "success" || stringPtrValue(a.Action) != "publish" {
					t.Fatalf("wrong ownership/outcome: %+v", a)
				}
				if a.Metadata["publication_scope"] != "tenant_override" || a.Metadata["artifact_sha256"] != digest || a.Metadata["artifact_size"] != float64(len(body)) || a.Metadata["file_name"] != "program.tar.gz" || a.Metadata["version"] != []string{"build-a", "build-b"}[index] {
					t.Fatalf("wrong content: %v", a.Metadata)
				}
				if mode == "selected-tenant" && (a.Metadata["operator_tenant_id"] != owner || a.Metadata["operator_principal_id"] != "publisher") {
					t.Fatal("operator attribution lost")
				}
				if _, err := time.Parse(time.RFC3339, a.Timestamp); err != nil {
					t.Fatal(err)
				}
				index++
			}
			mirrored := 0
			for _, a := range outbox.insertedAudits {
				if a.EventType == "admin_connector_program_published" {
					mirrored++
					if a.TenantID != target || stringPtrValue(a.ActorUserID) != "publisher" || a.Metadata["artifact_sha256"] != digest {
						t.Fatal("outbox loses content/ownership")
					}
				}
			}
			if mirrored != 2 {
				t.Fatal("missing mirrors")
			}
			if r := request("PUT", path, strings.Repeat("0", 64), "rejected"); r.Code != 400 {
				t.Fatal("digest mismatch accepted")
			}
			if domainCount() != 2 {
				t.Fatal("rejection claimed publication")
			}
			if r := request("GET", "/admin/connector-programs", "", ""); r.Code != 200 {
				t.Fatal("read failed")
			}
			if domainCount() != 2 {
				t.Fatal("read emitted publication")
			}
			// A metadata failure can follow a byte write; it must not claim completed publication.
			meta := filepath.Join(root, "tenants", target, "linux-amd64", "program.json")
			if err := os.Remove(meta); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(meta, 0700); err != nil {
				t.Fatal(err)
			}
			if r := request("PUT", path, digest, "incomplete"); r.Code != 500 {
				t.Fatalf("metadata failure %d", r.Code)
			}
			if domainCount() != 2 {
				t.Fatal("incomplete publication claimed success")
			}
		})
	}
}

func TestConnectorPublicationAuditUsesRequestActor(t *testing.T) {
	meta := connectorProgramMeta{Platform: "linux", Arch: "arm64", PublishedBy: "untrusted-meta-actor"}
	for _, r := range []*http.Request{nil, httptest.NewRequest("PUT", "/", nil), adminRequestBy(" ")} {
		a := connectorProgramPublishedAuditLog(r, "target", meta, testEvaluator(), time.Now())
		if a.ActorUserID != nil {
			t.Fatal("invented actor")
		}
	}
	a := connectorProgramPublishedAuditLog(adminRequestBy(" publisher "), "target", meta, testEvaluator(), time.Now())
	if stringPtrValue(a.ActorUserID) != "publisher" || a.TenantID != "target" {
		t.Fatal("wrong caller/owner")
	}
}

func TestConnectorPublicationAuditFailureKeepsSavedProgram(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "logs", "audit.log.jsonl"), 0700); err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	mux := http.NewServeMux()
	root := filepath.Join(dir, "programs")
	registerConnectorProgramRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h(w, requestWithAdminIdentity(r, adminIdentity{PrincipalID: "publisher", TenantID: "target"}))
		}
	}, root, false, writer, outbox, testEvaluator())
	body := []byte("saved-program")
	r := publishConnectorProgram(t, mux, "linux", "amd64", body, sha256Of(body))
	if r.Code != 200 {
		t.Fatalf("publication response changed: %d", r.Code)
	}
	got, err := os.ReadFile(filepath.Join(root, "tenants", "target", "linux-amd64", "program"))
	if err != nil || string(got) != string(body) {
		t.Fatal("audit failure undid publication")
	}
	health := writer.AuditHealth()
	if health.Attempts != 1 || health.PrimaryFailures != 1 || health.Status != "degraded" {
		t.Fatalf("failure not observable: %+v", health)
	}
	if len(outbox.insertedAudits) != 0 {
		t.Fatal("failed primary audit was mirrored as confirmed")
	}
}
