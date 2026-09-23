package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestIncomingOperatorBodyTargetOwnsItsAudit(t *testing.T) {
	root := t.TempDir()
	w, err := logs.NewWriter(filepath.Join(root, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "operator-admin", TenantID: "operator", Roles: []string{"owner"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "operator-token", TokenHash: adminTokenHash("review-operator"), TenantID: "operator", CreatedByAdminPrincipalID: "operator-admin", Roles: []string{"owner"}, Scopes: []string{"*"}, Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	s := policy.NewStore(nil)
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), OperatorTenantID: "operator", AdminAuth: auth, Writer: w, PolicyStore: s})
	body := []byte(`{"id":"incoming","tenant_id":"customer","business_owner":"Customer owner","expires_at":"2027-01-01T00:00:00Z","mode":"allow"}`)
	req := httptest.NewRequest("POST", "/admin/legacy-exceptions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer review-operator")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Operate-Tenant", "customer")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != 200 {
		t.Fatalf("status %d: %s", res.Code, res.Body.String())
	}
	if len(s.LegacyExceptionsFor("customer")) != 1 || len(s.LegacyExceptionsFor("operator")) != 0 {
		t.Fatal("wrong stored tenant")
	}
	rows := inventoryMutationAudits(t, root)
	found := false
	for _, a := range rows {
		if a["event_type"] != "admin_incoming_changed" {
			continue
		}
		found = true
		b, _ := json.Marshal(a)
		if a["tenant_id"] != "customer" || a["actor_user_id"] != "operator-admin" {
			t.Fatalf("wrong audit %s", b)
		}
		meta := a["metadata"].(map[string]any)
		if meta["operator_tenant_id"] != "operator" || meta["target_tenant_id"] != "customer" {
			t.Fatal("missing attribution")
		}
	}
	if !found {
		t.Fatal("missing domain audit")
	}
}
