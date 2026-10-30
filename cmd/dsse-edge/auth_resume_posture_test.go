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
