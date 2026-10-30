package device

import (
	"errors"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

type inventorySnapshotPersister struct {
	loaded  []byte
	loadErr error
	saves   int
}

func (p *inventorySnapshotPersister) Load() ([]byte, error) { return p.loaded, p.loadErr }
func (p *inventorySnapshotPersister) Save(_ []byte) error   { p.saves++; return nil }

func TestSetPersisterRejectsInvalidSnapshotWithoutReplacingWriter(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	store := NewStore()
	working := &inventorySnapshotPersister{}
	if err := store.SetPersister(working); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Register(model.Device{ID: "device", TenantID: "tenant"}, model.PolicyBundle{}, now); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []*inventorySnapshotPersister{
		{loadErr: errors.New("disk read failed")},
		{loaded: []byte("not JSON")},
		{loaded: []byte("null")},
		{loaded: []byte("{}")},
		{loaded: []byte(`{"devices":null,"posture_policy":{}}`)},
		{loaded: []byte(`{"devices": {}, "posture_policy": null }`)},
	} {
		if err := store.SetPersister(candidate); err == nil {
			t.Fatalf("invalid snapshot was accepted: %q", candidate.loaded)
		}
		if store.persister != working {
			t.Fatal("failed load replaced the working persistence writer")
		}
		if dev, ok := store.Get("device"); !ok || dev.TenantID != "tenant" {
			t.Fatal("failed load changed the in-memory inventory")
		}
	}
	savedBefore := working.saves
	if _, err := store.Heartbeat(model.DeviceHeartbeat{ID: "device", TenantID: "tenant"}, model.PolicyBundle{}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if working.saves != savedBefore+1 {
		t.Fatal("next mutation did not save through the original writer")
	}
}

func TestSetPersisterAcceptsCompleteSnapshotWithDisabledPostureChecks(t *testing.T) {
	store := NewStore()
	snapshot := &inventorySnapshotPersister{loaded: []byte(`{"devices":{},"posture_policy":{}}`)}
	if err := store.SetPersister(snapshot); err != nil {
		t.Fatal(err)
	}
	if store.persister != snapshot || store.PosturePolicy() != (PosturePolicy{}) {
		t.Fatal("complete snapshot with an explicit zero-valued policy was not restored")
	}
}

func TestMalformedOSVersionNeverPassesMinimum(t *testing.T) {
	for _, got := range []string{"999.bad", "999.-1", "999..1", "-1", "garbage"} {
		if osVersionAtLeast(got, "14.0") {
			t.Fatalf("malformed OS version %q passed the minimum", got)
		}
	}
	if osVersionAtLeast("999", "14.bad") {
		t.Fatal("malformed policy minimum was treated as no floor")
	}
	if !osVersionAtLeast("14.5", "14.0") {
		t.Fatal("valid dotted version was rejected")
	}
}

func TestDeviceInputAndReadResultsDoNotShareMutableState(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	store := NewStore()
	good := true
	meta := map[string]any{"nested": map[string]any{"label": "original"}, "events": []any{map[string]any{"result": "original"}}, "typed": map[string][]string{"labels": {"original"}}}
	posture := &model.DevicePostureSignals{DiskEncryptionEnabled: &good, FirewallEnabled: &good, Source: "original"}
	if _, err := store.Register(model.Device{ID: "device", TenantID: "tenant", Metadata: meta, Posture: posture}, model.PolicyBundle{}, now); err != nil {
		t.Fatal(err)
	}
	meta["nested"].(map[string]any)["label"] = "changed by caller"
	meta["events"].([]any)[0].(map[string]any)["result"] = "changed by caller"
	meta["typed"].(map[string][]string)["labels"][0] = "changed by caller"
	posture.Source = "changed by caller"
	good = false
	check := func(stage string) {
		t.Helper()
		got, ok := store.Get("device")
		if !ok || got.Metadata["nested"].(map[string]any)["label"] != "original" ||
			got.Metadata["events"].([]any)[0].(map[string]any)["result"] != "original" ||
			got.Metadata["typed"].(map[string][]string)["labels"][0] != "original" ||
			got.Posture.Source != "original" || !*got.Posture.DiskEncryptionEnabled {
			t.Fatalf("%s changed stored state through an alias: %+v", stage, got)
		}
	}
	check("registration input")
	read, _ := store.Get("device")
	read.Metadata["nested"].(map[string]any)["label"] = "changed by read"
	read.Metadata["events"].([]any)[0].(map[string]any)["result"] = "changed by read"
	read.Metadata["typed"].(map[string][]string)["labels"][0] = "changed by read"
	read.Posture.Source = "changed by read"
	*read.Posture.DiskEncryptionEnabled = false
	check("Get result")
	listed := store.List()
	listed[0].Metadata["nested"].(map[string]any)["label"] = "changed by List"
	listed[0].Posture.Source = "changed by List"
	check("List result")

	good = true
	heartbeatMeta := map[string]any{"more": map[string]any{"value": "heartbeat"}}
	heartbeatPosture := &model.DevicePostureSignals{DiskEncryptionEnabled: &good, FirewallEnabled: &good, Source: "heartbeat"}
	if _, err := store.Heartbeat(model.DeviceHeartbeat{ID: "device", TenantID: "tenant", Metadata: heartbeatMeta, Posture: heartbeatPosture}, model.PolicyBundle{}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	heartbeatMeta["more"].(map[string]any)["value"] = "changed"
	heartbeatPosture.Source = "changed"
	got, _ := store.Get("device")
	if got.Metadata["more"].(map[string]any)["value"] != "heartbeat" || got.Posture.Source != "heartbeat" {
		t.Fatal("heartbeat input mutated stored state")
	}
}
