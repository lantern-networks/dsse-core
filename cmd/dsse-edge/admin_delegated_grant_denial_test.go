package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDelegatedRevokePartialAuditAndConfirmedRetry(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		name := "rejected"
		if replaced {
			name = "durability_unconfirmed"
		}
		t.Run(name, func(t *testing.T) {
			p := &revocationAuditPersister{replaceBeforeError: replaced, base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "grants.json")}}
			s := delegatedgrant.NewStore(0)
			w, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			out := &recordingAdminAuditOutboxDeadReader{}
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w, DelegatedGrants: s, AdminAuth: newAdminAuthStore(), AdminAuditOutbox: out})
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			for _, tenant := range []string{"tenant_lab_001", "foreign"} {
				if _, err := s.Upsert(model.DelegatedAccessGrant{ID: "same", TenantID: tenant, Status: "active", ActorNHIID: "agent", SubjectUserID: "person"}); err != nil {
					t.Fatal(err)
				}
			}
			for attempt := 0; attempt < 3; attempt++ {
				p.fail.Store(attempt < 2)
				r := httptest.NewRequest("POST", "/admin/delegated-grants/same/revoke", strings.NewReader(`{"revocation_reason_code":"private-reason"}`))
				response := httptest.NewRecorder()
				h.ServeHTTP(response, r)
				want := 200
				if attempt < 2 {
					want = 500
				}
				if response.Code != want {
					t.Fatalf("response %d %s", response.Code, response.Body)
				}
				if attempt < 2 {
					var body map[string]any
					json.Unmarshal(response.Body.Bytes(), &body)
					if body["status"] != "partial" || body["applied"] != true || body["persistence"] != "unconfirmed" || body["grant_id"] != "same" {
						t.Fatalf("missing partial %s", response.Body)
					}
				}
				grant, ok := s.GetForTenant("tenant_lab_001", "same")
				if !ok || delegatedgrant.IsActive(grant, time.Now()) {
					t.Fatal("failure restored allow")
				}
				if grant, ok := s.GetForTenant("foreign", "same"); !ok || !delegatedgrant.IsActive(grant, time.Now()) {
					t.Fatal("foreign grant affected")
				}
			}
			if len(out.insertedAudits) != 3 {
				t.Fatalf("domain audits %d", len(out.insertedAudits))
			}
			for i, a := range out.insertedAudits {
				if a.EventType != "admin_delegated_access_grant_revoked" || a.TenantID != "tenant_lab_001" || a.ActorUserID == nil || *a.ActorUserID == "" {
					t.Fatal("audit attribution")
				}
				if i < 2 && (stringPtrValue(a.Result) != "partial" || a.Metadata["applied"] != true || a.Metadata["persistence"] != "unconfirmed") {
					t.Fatal("partial audit missing")
				}
				raw, _ := json.Marshal(a)
				if strings.Contains(string(raw), "private-reason") {
					t.Fatal("private reason leaked into audit")
				}
			}
			restored := delegatedgrant.NewStore(0)
			if err := restored.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if grant, ok := restored.GetForTenant("tenant_lab_001", "same"); !ok || delegatedgrant.IsActive(grant, time.Now()) {
				t.Fatal("confirmed retry missing after restart")
			}
		})
	}
}
