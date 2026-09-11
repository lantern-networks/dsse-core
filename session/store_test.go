package session

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestCreateFromAuthenticationEvent(t *testing.T) {
	expiresAt := "2026-05-22T01:00:00Z"
	deviceID := "dev_lab_001"
	store := NewStore()
	session, err := store.CreateFromAuthenticationEvent(model.AuthenticationEvent{
		ID:        "auth_lab_001",
		TenantID:  "tenant_lab_001",
		UserID:    "user_lab_001",
		SessionID: "sess_lab_001",
		IDPID:     "idp_keycloak_lab",
		Method:    "oidc_authorization_code",
		MFAState:  "fresh",
		ExpiresAt: &expiresAt,
		DeviceID:  &deviceID,
		Result:    "success",
		Timestamp: "2026-05-22T00:00:00Z",
		Metadata: map[string]any{
			"issuer": "https://accounts.google.com",
			"groups": []string{"/workspace/example.com"},
		},
	}, "pb_lab_20260522_001", "tenant_lab_001", time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("CreateFromAuthenticationEvent returned error: %v", err)
	}
	if session.ID != "sess_lab_001" {
		t.Fatalf("session id = %q, want sess_lab_001", session.ID)
	}
	if session.AuthenticationEventID != "auth_lab_001" {
		t.Fatalf("authentication_event_id = %q", session.AuthenticationEventID)
	}
	if session.Metadata["mfa_state"] != "fresh" {
		t.Fatalf("mfa_state metadata = %v", session.Metadata["mfa_state"])
	}
	if session.Metadata["issuer"] != "https://accounts.google.com" {
		t.Fatalf("issuer metadata = %v", session.Metadata["issuer"])
	}
	groups, ok := session.Metadata["groups"].([]string)
	if !ok || len(groups) != 1 || groups[0] != "/workspace/example.com" {
		t.Fatalf("groups metadata = %#v", session.Metadata["groups"])
	}
}

func TestCreateFromAuthenticationEventRejectsTenantMismatch(t *testing.T) {
	store := NewStore()
	_, err := store.CreateFromAuthenticationEvent(model.AuthenticationEvent{
		ID:        "auth_lab_001",
		TenantID:  "tenant_other",
		UserID:    "user_lab_001",
		SessionID: "sess_lab_001",
		Result:    "success",
	}, "pb_lab_20260522_001", "tenant_lab_001", time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("CreateFromAuthenticationEvent returned nil error, want tenant mismatch")
	}
}
