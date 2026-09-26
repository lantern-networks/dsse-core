package main

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDownloadIssuerAttributionSurvivesRestore(t *testing.T) {
	for _, who := range []string{"operator", "customer"} {
		t.Run(who, func(t *testing.T) {
			dir := t.TempDir()
			w, err := logs.NewWriter(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			now := time.Now()
			auth := newAdminAuthStore()
			for _, a := range []struct {
				id, tenant string
				roles      []string
			}{{"operator", "operations", []string{"super_admin"}}, {"customer", "customer", []string{"admin"}}} {
				auth.UpsertPrincipal(adminPrincipal{ID: a.id, TenantID: a.tenant, Roles: a.roles, Status: "active"})
				auth.UpsertAPIToken(adminAPIToken{ID: a.id, TenantID: a.tenant, TokenHash: adminTokenHash("synthetic-" + a.id), Roles: a.roles, Scopes: []string{"*"}, CreatedByAdminPrincipalID: a.id, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
			}
			tenants := newOperatorAwareAdminTenantModelStore(model.PolicyBundle{}, now, "", "operations")
			for _, id := range []string{"operations", "customer"} {
				if _, err := tenants.Put(context.Background(), adminTenantModel{TenantID: id, DisplayName: id, Status: "active"}, now); err != nil {
					t.Fatal(err)
				}
			}
			delegate(t, tenants, "customer", true, false)
			jobs := newAdminExportJobStore()
			tokens := newAdminDownloadTokenStore()
			p := blobstore.FilePersister{Path: filepath.Join(dir, "tokens.json")}
			if err := tokens.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			// Opposite creator attribution must never become the link issuer's identity.
			job := jobs.Create(adminExportJobRequest{Stream: "access"}, "customer", "different-creator", now)
			if _, err := jobs.MarkRunning(job.ID, now); err != nil {
				t.Fatal(err)
			}
			if _, err := jobs.MarkCompleted(job.ID, 1, 1, false, "evidence://tenant/customer/result.gz", "sha256:synthetic", now); err != nil {
				t.Fatal(err)
			}
			jobs.mu.Lock()
			j := jobs.jobs[job.ID]
			j.Metadata["operator_tenant_id"] = "creator-home"
			jobs.jobs[job.ID] = j
			jobs.mu.Unlock()
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w, AdminAuth: auth, TenantModelStore: tenants, OperatorTenantID: "operations", AdminExportJobs: jobs, AdminDownloadTokens: tokens})
			code, raw := operatorEnvelopeCall(t, h, "synthetic-"+who, "POST", "/admin/export-jobs/"+job.ID+"/download-url", "customer", map[string]any{"operator_tenant_id": "forged"})
			if code != 201 {
				t.Fatalf("issue %d %s", code, raw)
			}
			var reply adminDownloadURLResponse
			if err := json.Unmarshal([]byte(raw), &reply); err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(reply.DownloadURL)
			if err != nil {
				t.Fatal(err)
			}
			// Supply fixture bytes in the persisted token; no export object is needed on the receiving node.
			b, err := os.ReadFile(p.Path)
			if err != nil {
				t.Fatal(err)
			}
			var saved map[string]adminDownloadToken
			json.Unmarshal(b, &saved)
			for key, tok := range saved {
				tok.Payload = []byte("synthetic-export")
				saved[key] = tok
			}
			b, _ = json.Marshal(saved)
			if err := os.WriteFile(p.Path, b, 0600); err != nil {
				t.Fatal(err)
			}
			restored := newAdminDownloadTokenStore()
			if err := restored.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			receiving := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w, AdminDownloadTokens: restored})
			rr := httptest.NewRecorder()
			receiving.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, u.RequestURI(), nil))
			if rr.Code != 200 || rr.Body.String() != "synthetic-export" {
				t.Fatalf("download %d", rr.Code)
			}
			audit, err := os.ReadFile(filepath.Join(dir, "audit.log.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, line := range strings.Split(strings.TrimSpace(string(audit)), "\n") {
				var a model.AuditLog
				if err := json.Unmarshal([]byte(line), &a); err != nil {
					t.Fatal(err)
				}
				if a.EventType != "admin_export_url_issued" && a.EventType != "admin_export_downloaded" {
					continue
				}
				count++
				if a.TenantID != "customer" || a.Metadata["issued_by_admin_principal_id"] != who {
					t.Fatal("wrong tenant or issuer")
				}
				if who == "operator" {
					if a.Metadata["issued_by_operator_tenant_id"] != "operations" {
						t.Fatalf("%s missing issuer home", a.EventType)
					}
				} else if _, ok := a.Metadata["issued_by_operator_tenant_id"]; ok {
					t.Fatal("customer inherited operator")
				}
				if a.EventType == "admin_export_url_issued" && who == "operator" {
					if a.Metadata["operator_tenant_id"] != "operations" || a.Metadata["operator_principal_id"] != who {
						t.Fatal("issue actor missing")
					}
				}
				if a.EventType == "admin_export_downloaded" {
					if a.ActorUserID == nil || *a.ActorUserID != "anonymous_token_bearer" || a.Metadata["download_actor_known"] != false {
						t.Fatal("bearer misattributed")
					}
					if _, ok := a.Metadata["operator_tenant_id"]; ok {
						t.Fatal("bearer marked operator")
					}
				}
				if strings.Contains(line, strings.TrimPrefix(u.Path, "/admin/export-downloads/")) {
					t.Fatal("bearer leaked to audit")
				}
			}
			if count != 2 {
				t.Fatalf("audit count %d", count)
			}
		})
	}
}
