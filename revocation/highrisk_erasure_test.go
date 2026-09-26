package revocation

import (
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"reflect"
	"testing"
)

type riskErasurePersister struct {
	riskFlushPersister
	writes int
}

func (p *riskErasurePersister) Save(b []byte) error { p.writes++; return p.riskFlushPersister.Save(b) }
func TestRiskErasureSaveOutcomesAndSharedUserWrite(t *testing.T) {
	bridge := errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	for _, tc := range []struct {
		name             string
		err              error
		retain, accepted bool
	}{
		{"atomic", nil, true, true}, {"in_place", blobstore.ErrSavedWithoutAtomicity, true, true},
		{"no_write", errors.New("private path"), false, false}, {"write_error", errors.New("private path"), true, false},
		{"unconfirmed_lost", blobstore.ErrDurabilityUnconfirmed, false, false}, {"unconfirmed_retained", blobstore.ErrDurabilityUnconfirmed, true, false},
		{"bridge_lost", bridge, false, false}, {"bridge_retained", bridge, true, false},
		{"wrapped_lost", fmt.Errorf("private path: %w", bridge), false, false}, {"wrapped_retained", fmt.Errorf("private path: %w", bridge), true, false},
	} {
		for _, op := range []string{"devices", "users", "tenant"} {
			t.Run(tc.name+"/"+op, func(t *testing.T) {
				p := &riskErasurePersister{}
				o := NewHighRiskOverlay()
				o.SetPersister(p)
				o.Mark("Owned", "high")
				o.Mark("owned", "critical")
				o.Mark("foreign", "medium")
				for _, tenant := range []string{"own", "foreign"} {
					if _, err := o.SetUserRisk(UserRisk{TenantID: tenant, ID: "same", Severity: "high"}); err != nil {
						t.Fatal(err)
					}
				}
				devices, users, gen, writes := o.Snapshot(), o.UserSnapshot(), o.ConfigGeneration(), p.writes
				mutate := func() (int, error) {
					switch op {
					case "devices":
						return o.RemoveDevicesChecked([]string{" Owned ", "Owned", "missing"})
					case "users":
						return o.RemoveUsers("own")
					default:
						return o.RemoveTenantRisksChecked("own", []string{" Owned ", "Owned", "missing"})
					}
				}
				want := 1
				if op == "tenant" {
					want = 2
				}
				p.err, p.retain = tc.err, tc.retain
				n, err := mutate()
				if (err == nil) != tc.accepted || (tc.accepted && n != want) || (!tc.accepted && (n != 0 || err != ErrRiskSave)) {
					t.Fatal(n, err)
				}
				if p.writes != writes+1 {
					t.Fatal("not one shared save")
				}
				if !tc.accepted && (!reflect.DeepEqual(devices, o.Snapshot()) || !reflect.DeepEqual(users, o.UserSnapshot()) || o.ConfigGeneration() != gen) {
					t.Fatal("failed removal published")
				}
				if tc.accepted && o.ConfigGeneration() != gen+1 {
					t.Fatal("missing generation")
				}
				loaded := NewHighRiskOverlay()
				loaded.SetPersister(p)
				deviceGone := loaded.Snapshot()["Owned"] == ""
				userGone := loaded.CountUsers("own") == 0
				if deviceGone != (tc.retain && op != "users") || userGone != (tc.retain && op != "devices") {
					t.Fatal("wrong saved outcome")
				}
				if loaded.Snapshot()["owned"] != "critical" || loaded.Snapshot()["foreign"] != "medium" || loaded.CountUsers("foreign") != 1 {
					t.Fatal("case or foreign namespace changed")
				}
				p.err = nil
				// A separate checked user write must not carry an unconfirmed device or
				// tenant-user erasure into the shared snapshot.
				if _, err := o.SetUserRisk(UserRisk{TenantID: "foreign", ID: "second", Severity: "critical"}); err != nil {
					t.Fatal(err)
				}
				loaded = NewHighRiskOverlay()
				loaded.SetPersister(p)
				if !tc.accepted && (loaded.Snapshot()["Owned"] != "high" || loaded.CountUsers("own") != 1) {
					t.Fatal("unconfirmed removal leaked into later user save")
				}
				n, err = mutate()
				if err != nil || (tc.accepted && n != 0) || (!tc.accepted && n != want) {
					t.Fatal("retry", n, err)
				}
				if o.ConfigGeneration() != gen+2 {
					t.Fatal("retry changed generation more than once")
				}
				// An already empty live selection still retries persistence, without churn.
				before := p.writes
				generation := o.ConfigGeneration()
				p.err = bridge
				p.retain = false
				if n, err := mutate(); n != 0 || err != ErrRiskSave {
					t.Fatal("empty retry falsely acknowledged", n, err)
				}
				p.err = nil
				if n, err := mutate(); n != 0 || err != nil {
					t.Fatal(n, err)
				}
				if p.writes != before+2 || o.ConfigGeneration() != generation {
					t.Fatal("empty retry save/generation")
				}
				loaded = NewHighRiskOverlay()
				loaded.SetPersister(p)
				if !reflect.DeepEqual(o.Snapshot(), loaded.Snapshot()) || !reflect.DeepEqual(o.UserSnapshot(), loaded.UserSnapshot()) {
					t.Fatal("reconciled state differs on reload")
				}
			})
		}
	}
}
func TestRiskErasureRefusesUnavailableOrLegacyState(t *testing.T) {
	for _, data := range []string{`{`, `{"schema_version":"unknown","devices":{}}`, `{"schema_version":"high_risk_overlay_state.v1","devices":{"legacy":"high"}}`} {
		t.Run(data, func(t *testing.T) {
			p := &riskErasurePersister{riskFlushPersister: riskFlushPersister{data: []byte(data)}}
			o := NewHighRiskOverlay()
			o.SetPersister(p)
			gen := o.ConfigGeneration()
			before := o.Snapshot()
			if n, err := o.RemoveTenantRisksChecked("own", []string{"legacy"}); n != 0 || err != ErrRiskUnavailable {
				t.Fatal(n, err)
			}
			if p.writes != 0 || gen != o.ConfigGeneration() || !reflect.DeepEqual(before, o.Snapshot()) {
				t.Fatal("unavailable state changed")
			}
		})
	}
}
func TestLegacyDeviceErasurePreservesMarksOnSaveFailure(t *testing.T) {
	p := &riskErasurePersister{}
	o := NewHighRiskOverlay()
	o.SetPersister(p)
	o.Mark("owned", "high")
	gen := o.ConfigGeneration()
	p.err = errors.New("failure")
	if n := o.RemoveDevices([]string{"owned"}); n != 0 || o.Snapshot()["owned"] != "high" || o.ConfigGeneration() != gen {
		t.Fatal("legacy false removal")
	}
	p.err = nil
	if n := o.RemoveDevices([]string{"owned"}); n != 1 {
		t.Fatal(n)
	}
}
func TestRiskErasureVolatileAndEmptyInputs(t *testing.T) {
	var absent *HighRiskOverlay
	if n, err := absent.RemoveTenantRisksChecked("own", []string{"dev"}); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	o := NewHighRiskOverlay()
	o.Mark("dev", "high")
	if n, err := o.RemoveTenantRisksChecked("", nil); n != 0 || err != nil || o.Snapshot()["dev"] != "high" {
		t.Fatal(n, err)
	}
	if n, err := o.RemoveDevicesChecked([]string{"dev"}); n != 1 || err != nil {
		t.Fatal(n, err)
	}
}
