package device

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestStoreRegisterHeartbeatAndGet(t *testing.T) {
	store := NewStore()
	bundle := model.PolicyBundle{
		ID:       "pb_lab_20260522_001",
		TenantID: "tenant_lab_001",
		Version:  "2026.05.22.001",
	}
	now := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)

	dev, err := store.Register(model.Device{
		ID:               "dev_lab_001",
		TenantID:         "tenant_lab_001",
		UserID:           "user_lab_001",
		Hostname:         "macbook-lab",
		OS:               "macos",
		OSVersion:        "15.5",
		AgentVersion:     "0.1.0",
		DeviceTrustLevel: "managed",
	}, bundle, now)
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if dev.PolicyBundleID != bundle.ID || dev.PolicyBundleVersion != bundle.Version {
		t.Fatalf("policy bundle = %s/%s", dev.PolicyBundleID, dev.PolicyBundleVersion)
	}

	updated, err := store.Heartbeat(model.DeviceHeartbeat{
		ID:               "dev_lab_001",
		TenantID:         "tenant_lab_001",
		AgentVersion:     "0.1.1",
		DeviceTrustLevel: "managed",
		Status:           "healthy",
		Metadata:         map[string]any{"network": "lab"},
	}, bundle, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Heartbeat returned error: %v", err)
	}
	if updated.AgentVersion != "0.1.1" || updated.Status != "healthy" {
		t.Fatalf("updated = %#v", updated)
	}
	if updated.Metadata["network"] != "lab" {
		t.Fatalf("metadata = %#v", updated.Metadata)
	}

	got, ok := store.Get("dev_lab_001")
	if !ok {
		t.Fatalf("device should exist")
	}
	if got.LastSeenAt == got.RegisteredAt {
		t.Fatalf("last_seen_at should advance")
	}
}

// Get/List must not hand out the store's internal Metadata map by reference: a caller iterating it
// while a heartbeat or risk signal writes into it is a Go-fatal concurrent map access (Edge crash).
// Run with -race to catch a regression as a data race even before it becomes a runtime throw.
func TestStoreReadsAreConcurrencySafeAgainstMetadataWrites(t *testing.T) {
	store := NewStore()
	bundle := model.PolicyBundle{ID: "pb_lab_001", TenantID: "tenant_lab_001", Version: "1"}
	now := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	if _, err := store.Register(model.Device{ID: "dev_lab_001", TenantID: "tenant_lab_001"}, bundle, now); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_, _ = store.Heartbeat(model.DeviceHeartbeat{
				ID:       "dev_lab_001",
				Metadata: map[string]any{"network": "lab", "seq": i},
			}, bundle, now.Add(time.Duration(i)*time.Second))
			_, _, _, _ = store.ApplyRiskSignal("dev_lab_001", model.RiskSignal{
				EntityID: "dev_lab_001", Severity: "high", Source: "test",
			}, now.Add(time.Duration(i)*time.Second))
		}
	}()
	for i := 0; i < 200; i++ {
		if dev, ok := store.Get("dev_lab_001"); ok {
			for range dev.Metadata {
			}
		}
		for _, dev := range store.List() {
			for range dev.Metadata {
			}
		}
	}
	<-done
}

func TestStoreRejectsTenantMismatch(t *testing.T) {
	store := NewStore()
	_, err := store.Register(model.Device{
		ID:       "dev_lab_001",
		TenantID: "tenant_other",
	}, model.PolicyBundle{TenantID: "tenant_lab_001"}, time.Now())
	if err == nil {
		t.Fatalf("Register should reject tenant mismatch")
	}
}
