package enrolledinventory

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type inventorySnapshotMemory struct {
	data    []byte
	loadErr error
	saves   int
}

func (p *inventorySnapshotMemory) Load() ([]byte, error) {
	return append([]byte(nil), p.data...), p.loadErr
}
func (p *inventorySnapshotMemory) Save(b []byte) error {
	p.saves++
	p.data = append([]byte(nil), b...)
	return nil
}

const inventoryComplete = `{"schema_version":"enrolled_inventory_state.v2","entries":{"device":{"identity":"device","enabled":false,"tenant_id":"tenant_a"}},"groups":{"group":{"id":"group","name":"Finance","tenant_id":"tenant_a","risk":"high"}}}`

func TestInventoryRestoreRejectsIncompleteSnapshots(t *testing.T) {
	cases := map[string]string{
		"null": "null", "array": "[]", "empty": "{}", "missing entries": `{"schema_version":"enrolled_inventory_state.v2"}`, "null entries": strings.Replace(inventoryComplete, `"entries":{`, `"entries":null,"other":{`, 1),
		"unknown schema": strings.Replace(inventoryComplete, "state.v2", "state.v9", 1), "null schema": strings.Replace(inventoryComplete, `"enrolled_inventory_state.v2"`, `null`, 1),
		"duplicate entry key":   strings.Replace(inventoryComplete, `"entries":{`, `"entries":{"device":{"identity":"device","enabled":true},`, 1),
		"null groups":           strings.Replace(inventoryComplete, `"groups":{"group":{"id":"group","name":"Finance","tenant_id":"tenant_a","risk":"high"}}`, `"groups":null`, 1),
		"duplicate group field": strings.Replace(inventoryComplete, `"name":"Finance"`, `"name":"Other","name":"Finance"`, 1),
		"duplicate root":        strings.Replace(inventoryComplete, `"entries":`, `"entries":{},"entries":`, 1), "case alias": strings.Replace(inventoryComplete, `"enabled"`, `"Enabled"`, 1), "duplicate row": strings.Replace(inventoryComplete, `"enabled":false`, `"enabled":true,"enabled":false`, 1),
		"missing enabled": strings.Replace(inventoryComplete, `"enabled":false,`, "", 1), "null enabled": strings.Replace(inventoryComplete, `"enabled":false`, `"enabled":null`, 1), "wrong boolean": strings.Replace(inventoryComplete, `"enabled":false`, `"enabled":"false"`, 1),
		"identity mismatch": strings.Replace(inventoryComplete, `"identity":"device"`, `"identity":"other"`, 1), "unknown kind": strings.Replace(inventoryComplete, `"enabled":false`, `"enabled":false,"kind":"unknown"`, 1), "negative nonce": strings.Replace(inventoryComplete, `"enabled":false`, `"enabled":false,"reenrolment_nonce":-1`, 1),
		"enabled tombstone": strings.Replace(inventoryComplete, `"enabled":false`, `"enabled":true,"removed_at":"then"`, 1), "group id mismatch": strings.Replace(inventoryComplete, `"id":"group"`, `"id":"other"`, 1), "null group row": strings.Replace(inventoryComplete, `{"id":"group","name":"Finance","tenant_id":"tenant_a","risk":"high"}`, `null`, 1),
		"unknown field": strings.Replace(inventoryComplete, `"enabled":false`, `"enabled":false,"enabled extra":true`, 1), "trailing": inventoryComplete + `{}`, "invalid utf8": inventoryComplete[:len(inventoryComplete)-1] + string([]byte{0xff}) + "}",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			p := &inventorySnapshotMemory{data: []byte(inventoryComplete)}
			l := NewLedger()
			if err := l.SetPersisterChecked(p); err != nil {
				t.Fatal(err)
			}
			entries, groups, gen := l.List(), l.ListGroups(), l.ConfigGeneration()
			p.data = []byte(raw)
			changed, err := l.ReloadFromStore()
			if !errors.Is(err, ErrInventoryLoad) || changed {
				t.Fatalf("accepted invalid input: changed=%t err=%v", changed, err)
			}
			if !reflect.DeepEqual(entries, l.List()) || !reflect.DeepEqual(groups, l.ListGroups()) || gen != l.ConfigGeneration() || p.saves != 0 {
				t.Fatal("failed restore published or saved")
			}
			if _, err := l.SetEnabledChecked("device", true, "now"); err == nil || p.saves != 0 {
				t.Fatal("write reached unread snapshot")
			}
			p.data = []byte(inventoryComplete)
			if _, err := l.ReloadFromStore(); err != nil {
				t.Fatal(err)
			}
			if _, err := l.SetEnabledChecked("device", true, "now"); err != nil || p.saves != 1 {
				t.Fatalf("repaired writer unavailable: %v", err)
			}
		})
	}
}
func TestInventoryReloadReplacesGroupsAndAdvancesCompleteGeneration(t *testing.T) {
	p := &inventorySnapshotMemory{data: []byte(inventoryComplete)}
	l := NewLedger()
	l.SetPersisterChecked(p)
	gen := l.ConfigGeneration()
	if changed, err := l.ReloadFromStore(); err != nil || changed || l.ConfigGeneration() != gen {
		t.Fatal("same state churn")
	}
	p.data = []byte(strings.Replace(inventoryComplete, `,"groups":{"group":{"id":"group","name":"Finance","tenant_id":"tenant_a","risk":"high"}}`, "", 1))
	if changed, err := l.ReloadFromStore(); err != nil || !changed || len(l.ListGroups()) != 0 || l.ConfigGeneration() != gen+1 {
		t.Fatal("omitted registry kept deleted groups")
	}
	gen = l.ConfigGeneration()
	p.data = []byte(strings.Replace(string(p.data), `"enabled":false`, `"enabled":false,"note":"new note"`, 1))
	if changed, err := l.ReloadFromStore(); err != nil || !changed || l.ConfigGeneration() != gen+1 {
		t.Fatal("metadata change not versioned")
	}
	if p.saves != 0 {
		t.Fatal("reload wrote")
	}
}
func TestInventoryMissingKnownStateAndLoadFailureRecover(t *testing.T) {
	p := &inventorySnapshotMemory{}
	l := NewLedger()
	l.SeedFromStatic(map[string]struct{}{"seed": {}}, "now")
	if err := l.SetPersisterChecked(p); err != nil || !l.IsAdmitted("seed") {
		t.Fatal("first boot seed")
	}
	p.data = []byte(inventoryComplete)
	l.ReloadFromStore()
	p.data = nil
	if _, err := l.ReloadFromStore(); !errors.Is(err, ErrInventoryLoad) {
		t.Fatal("missing known snapshot accepted")
	}
	p.data = []byte(`{"schema_version":"enrolled_inventory_state.v2","entries":{}}`)
	if _, err := l.ReloadFromStore(); err != nil || len(l.List()) != 0 || len(l.ListGroups()) != 0 {
		t.Fatal("complete empty repair")
	}
	p.loadErr = errors.New("private path backend")
	if _, err := l.ReloadFromStore(); err != ErrInventoryLoad {
		t.Fatal("backend detail escaped")
	}
	p.loadErr = nil
	if _, err := l.ReloadFromStore(); err != nil {
		t.Fatal(err)
	}
	fresh := NewLedger()
	p2 := &inventorySnapshotMemory{}
	fresh.SetPersisterChecked(p2)
	fresh.Enroll("device", "tenant_a", "", "now")
	p2.data = nil
	if _, err := fresh.ReloadFromStore(); err == nil {
		t.Fatal("saved snapshot disappearance accepted")
	}
}
func TestInventoryLegacyMigrationAndTenantStateRemain(t *testing.T) {
	for _, version := range []string{`"schema_version":"enrolled_inventory_state.v1",`, ""} {
		raw := strings.Replace(inventoryComplete, `"schema_version":"enrolled_inventory_state.v2",`, version, 1)
		f, err := decodeInventorySnapshot([]byte(raw))
		if err != nil || f.Entries["device"].DeviceEnrolledAt != migratedDeviceEnrolmentSentinel {
			t.Fatal("legacy enrolment protection lost")
		}
	}
	p := &inventorySnapshotMemory{}
	a := NewLedger()
	a.SetPersister(p)
	a.Enroll("device", "tenant_a", "", "now")
	a.Enroll("foreign", "tenant_b", "", "now")
	a.CreateGroup("Finance", "tenant_b", "", "high", "now")
	b := NewLedger()
	b.SetPersister(p)
	a.SetEnabledChecked("device", false, "later")
	b.ReloadFromStore()
	if b.IsAdmitted("device") || !b.IsAdmitted("foreign") || b.GroupRiskByName("tenant_a", "Finance") != "" || b.GroupRiskByName("tenant_b", "Finance") != "high" {
		t.Fatal("tenant state crossed")
	}
}
