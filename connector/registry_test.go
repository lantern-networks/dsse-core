package connector

import (
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestRegistryRegisterAndHeartbeat(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)

	conn, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_lab_001",
		TenantID:       "tenant_lab_001",
		Name:           "Lab Connector",
		PrivateBaseURL: "http://127.0.0.1:18090",
	}, now)
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if conn.Status != "registered" {
		t.Fatalf("status = %q, want registered", conn.Status)
	}

	conn, err = registry.Heartbeat(model.ConnectorHeartbeat{
		ID:                  "conn_lab_001",
		TenantID:            "tenant_lab_001",
		Status:              "healthy",
		PolicyBundleID:      "pb_lab_20260522_001",
		PolicyBundleVersion: "2026.05.22.001",
		Metadata: map[string]any{
			"identity_sync": map[string]any{
				"configured": true,
				"status":     "imported",
			},
		},
	}, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Heartbeat returned error: %v", err)
	}
	if conn.Status != "healthy" {
		t.Fatalf("status = %q, want healthy", conn.Status)
	}
	if conn.Metadata["policy_bundle_id"] != "pb_lab_20260522_001" {
		t.Fatalf("metadata policy_bundle_id = %v", conn.Metadata["policy_bundle_id"])
	}
	identitySync, ok := conn.Metadata["identity_sync"].(map[string]any)
	if !ok {
		t.Fatalf("metadata identity_sync = %#v", conn.Metadata["identity_sync"])
	}
	if identitySync["configured"] != true || identitySync["status"] != "imported" {
		t.Fatalf("metadata identity_sync = %#v", identitySync)
	}
}

// A connector may re-report its reachable routes on the heartbeat so the Edge's discovery list stays current
// without a reconnect. Heartbeat updates the registered routes when present; a heartbeat that omits them
// (nil) leaves the registered routes unchanged (additive — an older connector never wipes them).
func TestRegistryHeartbeatRefreshesReachableRoutes(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	if _, err := registry.Register(model.ConnectorRegistration{
		ID: "conn_lab_001", TenantID: "tenant_lab_001", PrivateBaseURL: "http://127.0.0.1:18090",
		ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.0.0.0/24"}},
	}, now); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Heartbeat WITH routes -> registered set refreshed.
	conn, err := registry.Heartbeat(model.ConnectorHeartbeat{
		ID: "conn_lab_001", TenantID: "tenant_lab_001", Status: "healthy",
		ReachableRoutes: &model.ConnectorReachableRoutes{CIDRs: []string{"10.0.0.0/24", "10.1.0.0/24"}},
	}, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if len(conn.ReachableRoutes.CIDRs) != 2 {
		t.Fatalf("heartbeat with routes must refresh the registered set, got %v", conn.ReachableRoutes.CIDRs)
	}

	// Heartbeat WITHOUT routes (nil) -> registered set unchanged (not wiped).
	conn, err = registry.Heartbeat(model.ConnectorHeartbeat{
		ID: "conn_lab_001", TenantID: "tenant_lab_001", Status: "healthy",
	}, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if len(conn.ReachableRoutes.CIDRs) != 2 {
		t.Fatalf("a heartbeat omitting routes must leave the registered set unchanged, got %v", conn.ReachableRoutes.CIDRs)
	}
}

// An operator display name (rename) is server-managed: set via SetDisplayNameForTenant, surfaced by DisplayName,
// and PRESERVED across re-registration + heartbeats (the connector can't set/clear it). Empty clears it.
func TestRegistrySetDisplayNameSurvivesReRegister(t *testing.T) {
	r := NewRegistry()
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	base := model.ConnectorRegistration{ID: "c1", TenantID: "t1", Name: "raw-name", PrivateBaseURL: "http://127.0.0.1:1"}
	if _, err := r.Register(base, now); err != nil {
		t.Fatalf("register: %v", err)
	}
	conn, ok, err := r.SetDisplayNameForTenant("t1", "c1", "Tokyo DC connector")
	if err != nil || !ok {
		t.Fatalf("SetDisplayName ok=%v err=%v", ok, err)
	}
	if DisplayName(conn) != "Tokyo DC connector" {
		t.Fatalf("DisplayName = %q", DisplayName(conn))
	}
	// Re-register (the connector reconnects, still reporting raw-name) — the operator name must stick.
	conn, err = r.Register(base, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if DisplayName(conn) != "Tokyo DC connector" {
		t.Fatalf("rename must survive re-register, got %q", DisplayName(conn))
	}
	// A heartbeat must not clobber it either.
	conn, _ = r.Heartbeat(model.ConnectorHeartbeat{ID: "c1", TenantID: "t1", Status: "healthy"}, now.Add(2*time.Minute))
	if DisplayName(conn) != "Tokyo DC connector" {
		t.Fatalf("rename must survive a heartbeat, got %q", DisplayName(conn))
	}
	// Cross-tenant is rejected; empty clears it.
	if _, ok, err := r.SetDisplayNameForTenant("other", "c1", "x"); ok || err == nil {
		t.Fatalf("cross-tenant rename must fail, ok=%v err=%v", ok, err)
	}
	conn, _, _ = r.SetDisplayNameForTenant("t1", "c1", "")
	if DisplayName(conn) != "" {
		t.Fatalf("empty name must clear the override, got %q", DisplayName(conn))
	}
}

func TestRegistryHeartbeatCannotOverwriteRuntimeSecretHash(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	rotatedAt := now.Add(time.Minute).UTC().Format(time.RFC3339)

	_, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_lab_001",
		TenantID:       "tenant_lab_001",
		Name:           "Lab Connector",
		PrivateBaseURL: "http://127.0.0.1:18090",
		Metadata: map[string]any{
			runtimeSecretHashMetadataKey: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			runtimeSecretRotatedAtKey:    "spoofed",
			runtimeSecretRotatedByKey:    "connector",
		},
	}, now)
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if registered, ok := registry.Get("conn_lab_001"); !ok || registered.Metadata[runtimeSecretRotatedAtKey] != nil || registered.Metadata[runtimeSecretRotatedByKey] != nil {
		t.Fatalf("Register kept server-managed rotation metadata: ok=%v metadata=%#v", ok, registered.Metadata)
	}
	_, ok, err := registry.RotateRuntimeSecretHashWithMetadata("conn_lab_001", "sha256:1111111111111111111111111111111111111111111111111111111111111111", now.Add(time.Minute), "admin_001")
	if err != nil || !ok {
		t.Fatalf("RotateRuntimeSecretHashWithMetadata ok=%v err=%v", ok, err)
	}

	conn, err := registry.Heartbeat(model.ConnectorHeartbeat{
		ID:       "conn_lab_001",
		TenantID: "tenant_lab_001",
		Status:   "healthy",
		Metadata: map[string]any{
			runtimeSecretHashMetadataKey: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			runtimeSecretRotatedAtKey:    "spoofed-heartbeat",
			runtimeSecretRotatedByKey:    "connector",
			"identity_sync":              map[string]any{"configured": true},
		},
	}, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("Heartbeat returned error: %v", err)
	}
	if got := conn.Metadata[runtimeSecretHashMetadataKey]; got != "sha256:1111111111111111111111111111111111111111111111111111111111111111" {
		t.Fatalf("runtime secret hash = %v, want original hash", got)
	}
	if got := conn.Metadata[runtimeSecretRotatedAtKey]; got != rotatedAt {
		t.Fatalf("runtime rotated at = %v, want %s", got, rotatedAt)
	}
	if got := conn.Metadata[runtimeSecretRotatedByKey]; got != "admin_001" {
		t.Fatalf("runtime rotated by = %v, want admin_001", got)
	}
	if _, ok := conn.Metadata["identity_sync"]; !ok {
		t.Fatalf("identity_sync metadata was not merged: %#v", conn.Metadata)
	}
}

func TestRegistryRejectsInvalidRuntimeSecretHash(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		value any
	}{
		{name: "wrong type", value: 123},
		{name: "wrong prefix", value: "md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{name: "too short", value: "sha256:abc"},
		{name: "uppercase hex", value: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := registry.Register(model.ConnectorRegistration{
				ID:             "conn_" + strings.ReplaceAll(tt.name, " ", "_"),
				TenantID:       "tenant_lab_001",
				Name:           "Lab Connector",
				PrivateBaseURL: "http://127.0.0.1:18090",
				Metadata: map[string]any{
					runtimeSecretHashMetadataKey: tt.value,
				},
			}, now)
			if err == nil {
				t.Fatal("Register returned nil error, want invalid runtime hash")
			}
		})
	}
}

func TestRegistryRegisterRejectsCrossTenantOverwrite(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 5, 25, 3, 0, 0, 0, time.UTC)
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_shared_001",
		TenantID:       "tenant_lab_001",
		Name:           "Lab Connector",
		PrivateBaseURL: "http://connector.local",
	}, now); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_shared_001",
		TenantID:       "tenant_other",
		Name:           "Other Connector",
		PrivateBaseURL: "http://other-connector.local",
	}, now.Add(time.Minute)); err == nil {
		t.Fatal("cross-tenant Register returned nil error")
	}
	conn, ok := registry.Get("conn_shared_001")
	if !ok {
		t.Fatal("connector disappeared")
	}
	if conn.TenantID != "tenant_lab_001" || conn.PrivateBaseURL != "http://connector.local" {
		t.Fatalf("connector = %#v, want original tenant registration", conn)
	}
}

func TestRegistryRegisterPreservesRuntimeCredentialMetadata(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 5, 25, 3, 30, 0, 0, time.UTC)
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_runtime_001",
		TenantID:       "tenant_lab_001",
		Name:           "Runtime Connector",
		PrivateBaseURL: "http://connector.local",
		Metadata:       map[string]any{"owner": "connector"},
	}, now); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	hash := "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	rotatedAt := now.Add(time.Minute)
	if _, ok, err := registry.RotateRuntimeSecretHashForTenantWithMetadata("tenant_lab_001", "conn_runtime_001", hash, rotatedAt, "admin_001"); err != nil || !ok {
		t.Fatalf("RotateRuntimeSecretHashForTenantWithMetadata ok=%v err=%v", ok, err)
	}
	conn, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_runtime_001",
		TenantID:       "tenant_lab_001",
		Name:           "Runtime Connector Updated",
		PrivateBaseURL: "http://updated-connector.local",
		Metadata:       map[string]any{"owner": "connector_updated"},
	}, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second Register returned error: %v", err)
	}
	if conn.Metadata[runtimeSecretHashMetadataKey] != hash || conn.Metadata[runtimeSecretRotatedAtKey] != rotatedAt.UTC().Format(time.RFC3339) || conn.Metadata[runtimeSecretRotatedByKey] != "admin_001" {
		t.Fatalf("re-registered metadata = %#v, want preserved runtime credential metadata", conn.Metadata)
	}
	if conn.Metadata["owner"] != "connector_updated" || conn.PrivateBaseURL != "http://updated-connector.local" {
		t.Fatalf("re-registered connector = %#v, want updated non-secret fields", conn)
	}
}

func TestRegistryRegisterPreservesLifecycleState(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 5, 25, 4, 0, 0, 0, time.UTC)
	registered, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_lifecycle_001",
		TenantID:       "tenant_lab_001",
		Name:           "Lifecycle Connector",
		PrivateBaseURL: "http://connector.local",
	}, now)
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	heartbeatAt := now.Add(time.Minute)
	healthy, err := registry.Heartbeat(model.ConnectorHeartbeat{
		ID:       "conn_lifecycle_001",
		TenantID: "tenant_lab_001",
		Status:   "healthy",
	}, heartbeatAt)
	if err != nil {
		t.Fatalf("Heartbeat returned error: %v", err)
	}
	conn, err := registry.Register(model.ConnectorRegistration{
		ID:              "conn_lifecycle_001",
		TenantID:        "tenant_lab_001",
		Name:            "Lifecycle Connector Updated",
		PrivateBaseURL:  "http://updated-connector.local",
		Status:          "offline",
		RegisteredAt:    now.Add(2 * time.Hour).Format(time.RFC3339),
		LastHeartbeatAt: now.Add(2 * time.Hour).Format(time.RFC3339),
		Metadata:        map[string]any{"owner": "connector_updated"},
	}, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second Register returned error: %v", err)
	}
	if conn.Status != healthy.Status || conn.RegisteredAt != registered.RegisteredAt || conn.LastHeartbeatAt != healthy.LastHeartbeatAt {
		t.Fatalf("re-registered lifecycle state = status %q registered_at %q last_heartbeat_at %q, want %q %q %q", conn.Status, conn.RegisteredAt, conn.LastHeartbeatAt, healthy.Status, registered.RegisteredAt, healthy.LastHeartbeatAt)
	}
	if conn.Name != "Lifecycle Connector Updated" || conn.PrivateBaseURL != "http://updated-connector.local" || conn.Metadata["owner"] != "connector_updated" {
		t.Fatalf("re-registered connector = %#v, want updated profile fields", conn)
	}
}

func TestRegistryRotateRuntimeSecretHash(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC)
	_, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_lab_001",
		TenantID:       "tenant_lab_001",
		Name:           "Lab Connector",
		PrivateBaseURL: "http://127.0.0.1:18090",
		Metadata: map[string]any{
			"identity_sync": map[string]any{"configured": true},
		},
	}, now)
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	hash := "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	rotatedAt := now.Add(time.Hour)
	conn, ok, err := registry.RotateRuntimeSecretHashWithMetadata("conn_lab_001", hash, rotatedAt, "admin_001")
	if err != nil {
		t.Fatalf("RotateRuntimeSecretHash returned error: %v", err)
	}
	if !ok {
		t.Fatal("RotateRuntimeSecretHash returned ok=false")
	}
	if conn.Metadata[runtimeSecretHashMetadataKey] != hash {
		t.Fatalf("runtime hash = %v, want %s", conn.Metadata[runtimeSecretHashMetadataKey], hash)
	}
	if _, ok := conn.Metadata["identity_sync"]; !ok {
		t.Fatalf("rotation dropped existing metadata: %#v", conn.Metadata)
	}
	if got := conn.Metadata[runtimeSecretRotatedAtKey]; got != rotatedAt.UTC().Format(time.RFC3339) {
		t.Fatalf("runtime rotated at = %v, want %s", got, rotatedAt.UTC().Format(time.RFC3339))
	}
	if got := conn.Metadata[runtimeSecretRotatedByKey]; got != "admin_001" {
		t.Fatalf("runtime rotated by = %v, want admin_001", got)
	}

	if _, _, err := registry.RotateRuntimeSecretHash("conn_lab_001", "sha256:not-valid"); err == nil {
		t.Fatal("RotateRuntimeSecretHash returned nil error for invalid hash")
	}
	if _, ok, err := registry.RotateRuntimeSecretHash("conn_missing", hash); err != nil || ok {
		t.Fatalf("missing rotate ok=%v err=%v, want ok=false nil err", ok, err)
	}
}

func TestRegistryRotateRuntimeSecretHashForTenant(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 5, 25, 2, 0, 0, 0, time.UTC)
	if _, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_lab_001",
		TenantID:       "tenant_lab_001",
		Name:           "Lab Connector",
		PrivateBaseURL: "http://127.0.0.1:18090",
		Metadata:       map[string]any{},
	}, now); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	hash := "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	if _, ok, err := registry.RotateRuntimeSecretHashForTenantWithMetadata("tenant_other", "conn_lab_001", hash, now.Add(time.Minute), "admin_001"); err != nil || ok {
		t.Fatalf("cross-tenant rotate ok=%v err=%v, want ok=false nil err", ok, err)
	}
	conn, ok := registry.Get("conn_lab_001")
	if !ok {
		t.Fatal("connector disappeared")
	}
	if _, ok := conn.Metadata[runtimeSecretHashMetadataKey]; ok {
		t.Fatalf("cross-tenant rotate changed metadata: %#v", conn.Metadata)
	}
	conn, ok, err := registry.RotateRuntimeSecretHashForTenantWithMetadata("tenant_lab_001", "conn_lab_001", hash, now.Add(time.Minute), "admin_001")
	if err != nil || !ok {
		t.Fatalf("tenant rotate ok=%v err=%v", ok, err)
	}
	if conn.Metadata[runtimeSecretHashMetadataKey] != hash {
		t.Fatalf("runtime hash = %v, want %s", conn.Metadata[runtimeSecretHashMetadataKey], hash)
	}
}

func TestRegistryHeartbeatRejectsTenantMismatch(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	_, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_lab_001",
		TenantID:       "tenant_lab_001",
		Name:           "Lab Connector",
		PrivateBaseURL: "http://127.0.0.1:18090",
	}, now)
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	_, err = registry.Heartbeat(model.ConnectorHeartbeat{
		ID:       "conn_lab_001",
		TenantID: "tenant_other",
		Status:   "healthy",
	}, now.Add(time.Minute))
	if err == nil {
		t.Fatal("Heartbeat returned nil error, want tenant mismatch")
	}
}

func TestRegistryFindByApplicationID(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	_, err := registry.Register(model.ConnectorRegistration{
		ID:             "conn_lab_001",
		TenantID:       "tenant_lab_001",
		Name:           "Lab Connector",
		ApplicationIDs: []string{"app_dummy_https"},
		PrivateBaseURL: "http://127.0.0.1:18090",
		Status:         "healthy",
	}, now)
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	conn, ok := registry.FindByApplicationID("app_dummy_https")
	if !ok {
		t.Fatal("FindByApplicationID returned false")
	}
	if conn.ID != "conn_lab_001" {
		t.Fatalf("connector id = %q, want conn_lab_001", conn.ID)
	}
}
