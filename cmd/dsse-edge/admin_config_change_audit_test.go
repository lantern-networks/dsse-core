package main

import (
	"testing"

	"github.com/lantern-networks/dsse-core/decision"
)

// The uniform API-write audit (b): the builder must capture WHO (principal + email + roles + auth method),
// WHAT (method + path), and the OUTCOME (status → success/error), and it must be non-secret.
func TestAdminConfigChangeAuditLog(t *testing.T) {
	ev := decision.Evaluator{EdgeRegionID: "region-a", EdgeClusterID: "edge-1"}
	identity := adminIdentity{PrincipalID: "adm_123", TenantID: "t1", Roles: []string{"admin"}, AuthMethod: "admin_session"}

	ok := adminConfigChangeAuditLog(identity, "alice@corp.example", "Alice", "POST", "/admin/rules", 200, ev, "t1", "10.0.0.5", "node")
	if ok.EventType != "admin_config_change" {
		t.Fatalf("event_type = %q", ok.EventType)
	}
	if ok.ActorUserID == nil || *ok.ActorUserID != "adm_123" {
		t.Fatalf("actor_user_id = %v, want adm_123", ok.ActorUserID)
	}
	if ok.Result == nil || *ok.Result != "success" {
		t.Fatalf("result = %v, want success", ok.Result)
	}
	if ok.SourceIP == nil || *ok.SourceIP != "10.0.0.5" {
		t.Fatalf("source_ip = %v, want the caller IP (accountability)", ok.SourceIP)
	}
	for k, want := range map[string]any{
		"email": "alice@corp.example", "display_name": "Alice",
		"method": "POST", "path": "/admin/rules", "auth_method": "admin_session", "status_code": 200,
	} {
		if ok.Metadata[k] != want {
			t.Fatalf("metadata[%s] = %#v, want %#v", k, ok.Metadata[k], want)
		}
	}

	// A 4xx outcome records result=error (a rejected config-change attempt is still auditable).
	bad := adminConfigChangeAuditLog(identity, "", "", "DELETE", "/admin/rules/r1", 403, ev, "t1", "10.0.0.5", "node")
	if bad.Result == nil || *bad.Result != "error" {
		t.Fatalf("4xx result = %v, want error", bad.Result)
	}
	if _, present := bad.Metadata["email"]; present {
		t.Fatalf("empty email must be omitted, got %#v", bad.Metadata["email"])
	}

	// Legacy owner bearer: no named principal email — the auth_method marks it as the shared token.
	legacy := adminConfigChangeAuditLog(adminIdentity{PrincipalID: "admin_legacy_token", AuthMethod: "legacy_admin_token", Roles: []string{"owner"}}, "", "", "POST", "/admin/dlp-rules", 200, ev, "t1", "10.0.0.5", "curl")
	if legacy.Metadata["auth_method"] != "legacy_admin_token" {
		t.Fatalf("legacy auth_method = %#v", legacy.Metadata["auth_method"])
	}
}
