package device

import (
	"fmt"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// FoldRegistration applies the same domain rules as Store.Register to one
// authoritative prior record. Durable backends use it while holding their own
// transaction lock; this temporary store never becomes a second state owner.
func FoldRegistration(previous *model.Device, reported model.Device, bundle model.PolicyBundle, policy PosturePolicy, now time.Time) (model.Device, error) {
	store, err := foldStore(previous, reported.ID, policy)
	if err != nil {
		return model.Device{}, err
	}
	return store.Register(reported, bundle, now)
}

// FoldHeartbeat shares Store.Heartbeat's device-controlled and Edge-controlled
// field rules with durable backends.
func FoldHeartbeat(previous model.Device, reported model.DeviceHeartbeat, bundle model.PolicyBundle, policy PosturePolicy, now time.Time) (model.Device, error) {
	store, err := foldStore(&previous, reported.ID, policy)
	if err != nil {
		return model.Device{}, err
	}
	return store.Heartbeat(reported, bundle, now)
}

// FoldRiskSignal shares Store.ApplyRiskSignal's administrative risk update
// semantics without an in-memory authoritative copy of the device inventory.
func FoldRiskSignal(previous model.Device, signal model.RiskSignal, now time.Time) (model.Device, bool, error) {
	store, err := foldStore(&previous, previous.ID, DefaultPosturePolicy())
	if err != nil {
		return model.Device{}, false, err
	}
	updated, found, high, err := store.ApplyRiskSignal(previous.ID, signal, now)
	if !found && err == nil {
		return model.Device{}, false, fmt.Errorf("device %s disappeared while folding risk", previous.ID)
	}
	return updated, high, err
}

func foldStore(previous *model.Device, reportedID string, policy PosturePolicy) (*Store, error) {
	store := NewStore()
	store.posturePolicy = policy
	if previous != nil {
		if previous.ID == "" || previous.ID != reportedID {
			return nil, fmt.Errorf("prior device does not match reported device %s", reportedID)
		}
		store.devices[previous.ID] = detachMetadata(*previous)
	}
	return store, nil
}
