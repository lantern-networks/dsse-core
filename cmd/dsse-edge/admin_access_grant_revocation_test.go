package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminAccessGrantPartialRetryScopedAuditAndCookiePrivacy(t *testing.T) {
	now := time.Now()
	writer, e := logs.NewWriter(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "grant-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "grant-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("private-review-token"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "grant-admin", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth})
	s := theGrantStore.Load()
	p := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "grants.json")}}
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	const cookie = "private-access-cookie-value"
	const foreign = "private-foreign-cookie"
	for _, g := range []grantstore.Grant{{GrantID: cookie, TenantID: "tenant_lab_001", UserID: "private-subject", UserEmail: "private-person@example.invalid", Scope: "private/resource"}, {GrantID: foreign, TenantID: "TENANT_LAB_001"}} {
		if _, e := s.Mint(g, time.Hour, now); e != nil {
			t.Fatal(e)
		}
	}
	for _, step := range []struct {
		id     string
		fail   bool
		status int
	}{{foreign, false, 404}, {cookie, true, 500}, {cookie, true, 500}, {cookie, false, 200}} {
		p.fail.Store(step.fail)
		r := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/admin/grants/"+step.id+"/revoke", nil)
		req.Header.Set("Authorization", "Bearer private-review-token")
		h.ServeHTTP(r, req)
		if r.Code != step.status {
			t.Fatalf("HTTP %d want %d: %s", r.Code, step.status, r.Body)
		}
		if step.status == 500 {
			var body map[string]any
			json.Unmarshal(r.Body.Bytes(), &body)
			if body["status"] != "partial" || body["applied"] != true || body["grant_id"] != cookie || body["tenant_id"] != "tenant_lab_001" || body["persistence"] != "unconfirmed" || body["audit_ref"] != accessGrantAuditReference(cookie) {
				t.Fatal("incomplete partial response")
			}
		}
		if step.id == cookie && s.Valid(cookie, now) {
			t.Fatal("failed save re-enabled grant")
		}
		if !s.Valid(foreign, now) {
			t.Fatal("foreign grant revoked")
		}
	}
	rows := readTransportAudits(t, writer)
	if len(rows) != 7 {
		t.Fatalf("audits: %d", len(rows))
	}
	domain, partial := 0, 0
	for _, a := range rows {
		if a.EventType == "admin_access_grant_revoked" {
			domain++
			if stringPtrValue(a.TargetID) != accessGrantAuditReference(cookie) || stringPtrValue(a.ActorUserID) != "grant-admin" || a.TenantID != "tenant_lab_001" {
				t.Fatalf("attribution %+v", a)
			}
			if stringPtrValue(a.Result) == "partial" {
				partial++
				if a.Metadata["persistence"] != "unconfirmed" {
					t.Fatal("missing persistence")
				}
			}
		}
	}
	if domain != 3 || partial != 2 {
		t.Fatal("wrong domain/partial counts")
	}
	raw, _ := json.Marshal(rows)
	for _, secret := range []string{cookie, foreign, "private-review-token", "private-subject", "private-person@example.invalid", "private/resource", "private-runtime-location"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("audit leaked %s", secret)
		}
	}
	reload := grantstore.NewStore()
	if e := reload.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if reload.Valid(cookie, now) || !reload.Valid(foreign, now) {
		t.Fatal("saved scope changed")
	}
	// The catalogued analyst role lacks access-grant write permission.
	auth.UpsertPrincipal(adminPrincipal{ID: "grant-reader", TenantID: "tenant_lab_001", Roles: []string{"analyst"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "reader-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("private-reader-token"), Roles: []string{"analyst"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "grant-reader", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	r := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/admin/grants/"+foreign+"/revoke", nil)
	req.Header.Set("Authorization", "Bearer private-reader-token")
	h.ServeHTTP(r, req)
	if r.Code != 403 {
		t.Fatalf("reader revoke %d", r.Code)
	}
	raw, _ = json.Marshal(readTransportAudits(t, writer))
	for _, secret := range []string{cookie, foreign, "private-reader-token"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("denial audit leaked credential")
		}
	}
	if !s.Valid(foreign, now) {
		t.Fatal("denied request changed grant")
	}
}
func TestAdminAccessGrantAuditRedactsBearerPath(t *testing.T) {
	for _, prefix := range []string{"/admin/grants/", "/control/admin/grants/"} {
		for _, status := range []int{200, 403, 404, 500} {
			a := adminConfigChangeAuditLog(adminIdentity{TenantID: "tenant"}, "", "", "POST", prefix+"private-cookie"+"/revoke", status, testEvaluator(), "tenant", "", "")
			raw, _ := json.Marshal(a)
			for _, extra := range []model.AuditLog{
				adminOperateWithinTenantAuditLog(adminIdentity{TenantID: "operator"}, "tenant", "POST", prefix+"private-cookie/revoke", testEvaluator(), "", ""),
				adminBreakGlassUseAuditLog(adminIdentity{TenantID: "tenant"}, "POST", prefix+"private-cookie/revoke", testEvaluator(), "tenant", "", "")} {
				encoded, _ := json.Marshal(extra)
				if strings.Contains(string(encoded), "private-cookie") {
					t.Fatal("privileged audit leaked credential")
				}
			}
			if strings.Contains(string(raw), "private-cookie") || a.Metadata["grant_ref"] != accessGrantAuditReference("private-cookie") {
				t.Fatal("bearer leaked or correlation absent")
			}
		}
	}
}
