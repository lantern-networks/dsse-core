package device

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestRegisterDoesNotMoveExistingDeviceToAnotherTenant(t *testing.T) {
	store := NewStore()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	if _, err := store.Register(model.Device{ID: "same-device", TenantID: "tenant-a"}, model.PolicyBundle{TenantID: "tenant-a"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Register(model.Device{ID: "same-device", TenantID: "tenant-b"}, model.PolicyBundle{TenantID: "tenant-b"}, now); err == nil {
		t.Fatal("a second tenant took over the existing device id")
	}
	got, ok := store.Get("same-device")
	if !ok || got.TenantID != "tenant-a" {
		t.Fatalf("device owner changed after rejected registration: %+v, present=%v", got, ok)
	}
}

func TestSelfReportCannotForgeOrClearAdministrativeRisk(t *testing.T) {
	store := NewStore()
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	bundle := model.PolicyBundle{TenantID: "tenant-a"}
	forged := map[string]any{
		"risk_state_severity": "none", "admin_high_risk": false,
		"risk_state_id": "forged", "manual_high_risk": false,
		"network": "lan",
	}
	registered, err := store.Register(model.Device{ID: "device", TenantID: "tenant-a", Metadata: forged}, bundle, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"risk_state_severity", "admin_high_risk", "risk_state_id", "manual_high_risk"} {
		if _, ok := registered.Metadata[key]; ok {
			t.Fatalf("registration accepted self-reported %s", key)
		}
	}
	if registered.Metadata["network"] != "lan" {
		t.Fatal("ordinary metadata was discarded")
	}
	if _, found, high, err := store.ApplyRiskSignal("device", model.RiskSignal{EntityID: "device", Severity: "high", Source: "admin"}, now.Add(time.Second)); err != nil || !found || !high {
		t.Fatalf("admin risk mark: found=%v high=%v err=%v", found, high, err)
	}
	for _, report := range []model.DeviceHeartbeat{{ID: "device", TenantID: "tenant-a", Metadata: forged}, {ID: "device", TenantID: "tenant-a", Metadata: nil}} {
		if _, err := store.Heartbeat(report, bundle, now.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		got, _ := store.Get("device")
		if got.Metadata["risk_state_severity"] != "high" || got.Metadata["admin_high_risk"] != true || got.Metadata["manual_high_risk"] != nil {
			t.Fatalf("heartbeat changed administrative risk: %+v", got.Metadata)
		}
	}
	if _, err := store.Register(model.Device{ID: "device", TenantID: "tenant-a", Metadata: forged}, bundle, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get("device")
	if got.Metadata["risk_state_severity"] != "high" || got.Metadata["admin_high_risk"] != true || got.Metadata["manual_high_risk"] != nil {
		t.Fatalf("re-registration changed administrative risk: %+v", got.Metadata)
	}
}
