package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTenantSettingsAuditUsesAuthenticatedPrincipal(t *testing.T) {
	now := time.Now()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "settings-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "settings-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("settings-test-token"), CreatedByAdminPrincipalID: "settings-admin", Roles: []string{"admin"}, Scopes: []string{"admin.tenant.write"}, Status: "active", CreatedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	writer, err := logs.NewWriter(filepath.Join(t.TempDir(), "logs"))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: auth, Writer: writer})
	req := httptest.NewRequest("POST", "/admin/tenant", strings.NewReader(`{"display_name":"Customer","timezone":"Asia/Tokyo"}`))
	req.Header.Set("Authorization", "Bearer settings-test-token")
	req.Header.Set("X-Actor-User-ID", "forged-actor")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	found := false
	rawLog, err := os.ReadFile(filepath.Join(writer.Dir(), "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(rawLog)), "\n") {
		var a model.AuditLog
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatal(err)
		}
		if a.EventType != "admin_tenant_model_updated" {
			continue
		}
		found = true
		if a.ActorUserID != nil || a.Metadata["actor_admin_principal_id"] != "settings-admin" || a.Metadata["actor_tenant_id"] != "tenant_lab_001" || stringPtrValue(a.Result) != "success" {
			t.Fatalf("actor contract: %+v", a)
		}
		raw, _ := json.Marshal(a)
		for _, bad := range []string{"settings-test-token", "forged-actor"} {
			if strings.Contains(string(raw), bad) {
				t.Fatal("private input in audit")
			}
		}
	}
	if !found {
		t.Fatal("missing tenant settings audit")
	}
}
