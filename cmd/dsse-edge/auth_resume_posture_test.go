package main

import (
	"errors"
	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/model"
	"testing"
	"time"
)

type authCountingDeviceStore struct {
	deviceRuntimeStore
	device model.Device
	err    error
	reads  int
}

func (s *authCountingDeviceStore) GetByTenant(tenant, id string) (model.Device, bool, error) {
	s.reads++
	return s.device, s.device.TenantID == tenant && s.device.ID == id, s.err
}
func TestAuthDeviceReadFailureAndPostureSemantics(t *testing.T) {
	yes := true
	store := &authCountingDeviceStore{deviceRuntimeStore: devicestore.NewStore(), device: model.Device{ID: "device", TenantID: "tenant", DeviceTrustLevel: "noncompliant", Posture: &model.DevicePostureSignals{DiskEncryptionEnabled: &yes, FirewallEnabled: &yes, CollectedAt: time.Now().Format(time.RFC3339)}}}
	req := model.DecisionRequest{DeviceID: "device", TenantID: "tenant"}
	for range 2 {
		before := store.reads
		got, err := enrichSteerDeviceRequest(req, "", nil, store, nil, nil)
		if err != nil || got.DeviceTrustLevel != "noncompliant" {
			t.Fatal("missing CONNECT posture promoted inventory trust", got.DeviceTrustLevel, err)
		}
		if store.reads != before+1 {
			t.Fatal("inventory read more than once")
		}
	}
	store.err = errors.New("inventory unavailable")
	if _, err := enrichSteerDeviceRequest(req, "managed", nil, store, nil, nil); err == nil {
		t.Fatal("steer decision ignored unavailable inventory")
	}
}

func TestAuthResumeUsesCanonicalIdentityAndSignalObservationTimes(t *testing.T) {
	now := time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)
	yes, no := true, false
	for _, mode := range []string{"partial-negative", "explicit-clear", "newer-inventory", "other-tenant"} {
		t.Run(mode, func(t *testing.T) {
			runtime := newEndpointRuntimeStore()
			runtime.ingestFromReport("Mac-One", "tenant", "macOS", &yes, &yes, "collector", "", now)
			runtime.ingestFromReport("mac-one", "tenant", "", &no, nil, "collector", "", now.Add(2*time.Second))
			if mode == "explicit-clear" {
				runtime.m["mac-one"].posture.DiskEncryptionEnabled = nil
			}
			inventoryTime := now.Add(time.Second)
			if mode == "newer-inventory" {
				inventoryTime = now.Add(3 * time.Second)
			}
			store := &authCountingDeviceStore{deviceRuntimeStore: devicestore.NewStore(), device: model.Device{ID: "mac-one", TenantID: "tenant", DeviceTrustLevel: "managed", Posture: &model.DevicePostureSignals{DiskEncryptionEnabled: &yes, FirewallEnabled: &yes, CollectedAt: inventoryTime.Format(time.RFC3339Nano)}}}
			req := model.DecisionRequest{DeviceID: "Mac-One", TenantID: "tenant"}
			if mode == "other-tenant" {
				runtime.m["mac-one"].tenant = "Tenant"
			}
			got, err := enrichSteerDeviceRequest(req, "managed", runtime, store, nil, nil)
			want := "noncompliant"
			if mode == "newer-inventory" || mode == "other-tenant" {
				want = "managed"
			}
			if err != nil || got.DeviceTrustLevel != want {
				t.Fatalf("resume posture %s: trust=%q, want=%q, error=%v", mode, got.DeviceTrustLevel, want, err)
			}
		})
	}
}

func TestAuthResumeMixedCaseReadsActualInventoryAndLatestRisk(t *testing.T) {
	now := time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)
	yes, no := true, false
	store := devicestore.NewStore()
	bundle := model.PolicyBundle{TenantID: "tenant"}
	if _, err := store.Register(model.Device{ID: "mac-one", TenantID: "tenant", Posture: &model.DevicePostureSignals{DiskEncryptionEnabled: &no, FirewallEnabled: &yes, CollectedAt: now.Format(time.RFC3339Nano)}}, bundle, now); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.ApplyRiskSignal("mac-one", model.RiskSignal{Severity: "high", Source: "operator"}, now); err != nil {
		t.Fatal(err)
	}
	req := model.DecisionRequest{DeviceID: "Mac-One", TenantID: "tenant"}
	got, err := enrichSteerDeviceRequest(req, "", nil, store, nil, nil)
	if err != nil || got.DeviceTrustLevel != "noncompliant" || got.RiskStateSeverity != "high" || !got.AdminHighRisk {
		t.Fatalf("mixed-case request missed actual inventory: trust=%q risk=%q high=%t error=%v", got.DeviceTrustLevel, got.RiskStateSeverity, got.AdminHighRisk, err)
	}
	if _, err := store.Heartbeat(model.DeviceHeartbeat{ID: "mac-one", TenantID: "tenant", Posture: &model.DevicePostureSignals{DiskEncryptionEnabled: &yes, FirewallEnabled: &yes, CollectedAt: now.Add(time.Second).Format(time.RFC3339Nano)}}, bundle, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.ApplyRiskSignal("mac-one", model.RiskSignal{Severity: "critical", Source: "operator"}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err = enrichSteerDeviceRequest(req, "", nil, store, nil, nil)
	if err != nil || got.DeviceTrustLevel != "managed" || got.RiskStateSeverity != "critical" || !got.AdminHighRisk {
		t.Fatalf("mixed-case request missed latest inventory/risk: trust=%q risk=%q high=%t error=%v", got.DeviceTrustLevel, got.RiskStateSeverity, got.AdminHighRisk, err)
	}
	for _, request := range []model.DecisionRequest{{DeviceID: "unknown", TenantID: "tenant"}, {DeviceID: "Mac-One", TenantID: "Tenant"}} {
		got, err := enrichSteerDeviceRequest(request, "", nil, store, nil, nil)
		if err != nil || got.DeviceTrustLevel != "" || got.RiskStateSeverity != "" || got.AdminHighRisk {
			t.Fatalf("unknown/different-tenant request inherited inventory: trust=%q risk=%q high=%t error=%v", got.DeviceTrustLevel, got.RiskStateSeverity, got.AdminHighRisk, err)
		}
	}
}
