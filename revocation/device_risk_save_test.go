package revocation

import (
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"reflect"
	"testing"
)

func TestDeviceRiskCheckedSaveAndSharedUserWrite(t *testing.T) {
	bridge := errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	for _, tc := range []struct {
		name                      string
		err                       error
		retain, accepted, warning bool
	}{
		{"atomic", nil, true, true, false}, {"in_place", blobstore.ErrSavedWithoutAtomicity, true, true, true},
		{"no_write", errors.New("private path"), false, false, false}, {"write_error", errors.New("private path"), true, false, false},
		{"unconfirmed_lost", blobstore.ErrDurabilityUnconfirmed, false, false, false}, {"unconfirmed_retained", blobstore.ErrDurabilityUnconfirmed, true, false, false},
		{"bridge_lost", bridge, false, false, false}, {"bridge_retained", bridge, true, false, false},
		{"wrapped_lost", fmt.Errorf("private: %w", bridge), false, false, false}, {"wrapped_retained", fmt.Errorf("private: %w", bridge), true, false, false},
	} {
		for _, severity := range []string{"critical", "medium", "none"} {
			t.Run(tc.name+"/"+severity, func(t *testing.T) {
				p := &riskErasurePersister{}
				o := NewHighRiskOverlay()
				o.SetPersister(p)
				o.Mark("Owned", "high")
				o.Mark("owned", "critical")
				o.Mark("foreign", "medium")
				if _, err := o.SetUserRisk(UserRisk{TenantID: "foreign", ID: "Owned", Severity: "high"}); err != nil {
					t.Fatal(err)
				}
				gen := o.ConfigGeneration()
				before := o.Snapshot()
				users := o.UserSnapshot()
				writes := p.writes
				p.err, p.retain = tc.err, tc.retain
				warning, err := o.SetDeviceRisk(" Owned ", severity)
				if (err == nil) != tc.accepted || warning != tc.warning || (!tc.accepted && err != ErrRiskSave) {
					t.Fatal(warning, err)
				}
				if p.writes != writes+1 {
					t.Fatal("save not attempted")
				}
				if !tc.accepted && (!reflect.DeepEqual(before, o.Snapshot()) || o.ConfigGeneration() != gen) {
					t.Fatal("unconfirmed change published")
				}
				if !reflect.DeepEqual(users, o.UserSnapshot()) {
					t.Fatal("user namespace changed")
				}
				want := severity
				if want == "none" {
					want = ""
				}
				reload := NewHighRiskOverlay()
				reload.SetPersister(p)
				expectedDisk := "high"
				if tc.retain {
					expectedDisk = want
				}
				if reload.Snapshot()["Owned"] != expectedDisk || reload.Snapshot()["owned"] != "critical" || reload.Snapshot()["foreign"] != "medium" {
					t.Fatal("wrong disk or case namespace")
				}
				p.err = nil
				if _, err := o.SetUserRisk(UserRisk{TenantID: "foreign", ID: "another", Severity: "critical"}); err != nil {
					t.Fatal(err)
				}
				reload = NewHighRiskOverlay()
				reload.SetPersister(p)
				if !tc.accepted && reload.Snapshot()["Owned"] != "high" {
					t.Fatal("failed device change persisted by unrelated user")
				}
				if _, err := o.SetDeviceRisk("Owned", severity); err != nil {
					t.Fatal(err)
				}
				if o.ConfigGeneration() != gen+2 || o.Snapshot()["Owned"] != want {
					t.Fatal("retry state/generation")
				}
				writes = p.writes
				generation := o.ConfigGeneration()
				p.err = bridge
				p.retain = false
				if w, err := o.SetDeviceRisk("Owned", severity); w || err != ErrRiskSave {
					t.Fatal("same-value retry acknowledged uncertainty")
				}
				p.err = nil
				if _, err := o.SetDeviceRisk("Owned", severity); err != nil {
					t.Fatal(err)
				}
				if p.writes != writes+2 || o.ConfigGeneration() != generation {
					t.Fatal("same-value retry save/generation")
				}
				reload = NewHighRiskOverlay()
				reload.SetPersister(p)
				if !reflect.DeepEqual(o.Snapshot(), reload.Snapshot()) || !reflect.DeepEqual(o.UserSnapshot(), reload.UserSnapshot()) {
					t.Fatal("retry reload mismatch")
				}
			})
		}
	}
}
func TestLegacyDeviceRiskPreservesEscalationButRefusesUnsavedDowngrade(t *testing.T) {
	p := &riskErasurePersister{}
	o := NewHighRiskOverlay()
	o.SetPersister(p)
	p.err = errors.New("fail")
	o.Mark("owned", "high")
	if o.Snapshot()["owned"] != "high" {
		t.Fatal("legacy automatic escalation lost")
	}
	gen := o.ConfigGeneration()
	o.Mark("owned", "medium")
	o.Clear("owned")
	if o.Snapshot()["owned"] != "high" || o.ConfigGeneration() != gen {
		t.Fatal("legacy unsaved de-escalation published")
	}
	p.err = nil
	if _, err := o.SetUserRisk(UserRisk{TenantID: "foreign", ID: "user", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	reload := NewHighRiskOverlay()
	reload.SetPersister(p)
	if reload.Snapshot()["owned"] != "high" {
		t.Fatal("later user write carried failed clear")
	}
	o.Mark("owned", "medium")
	o.Clear("owned")
	if _, ok := o.IsHighRisk("owned"); ok {
		t.Fatal("healthy legacy clear failed")
	}
}
func TestDeviceRiskUnavailableAndInvalidDoNotWrite(t *testing.T) {
	for _, data := range []string{`{`, `{"schema_version":"unknown","devices":{}}`, `{"schema_version":"high_risk_overlay_state.v1","devices":{"legacy":"high"}}`} {
		t.Run(data, func(t *testing.T) {
			p := &riskErasurePersister{riskFlushPersister: riskFlushPersister{data: []byte(data)}}
			o := NewHighRiskOverlay()
			o.SetPersister(p)
			before := o.Snapshot()
			gen := o.ConfigGeneration()
			if w, err := o.SetDeviceRisk("legacy", "none"); w || err != ErrRiskUnavailable {
				t.Fatal(w, err)
			}
			o.Clear("legacy")
			o.Mark("legacy", "critical")
			if p.writes != 0 || !reflect.DeepEqual(before, o.Snapshot()) || o.ConfigGeneration() != gen {
				t.Fatal("unavailable changed")
			}
		})
	}
}
func TestDeviceRiskVolatileAndInputValidation(t *testing.T) {
	var absent *HighRiskOverlay
	if _, err := absent.SetDeviceRisk("dev", "high"); err != ErrRiskUnavailable {
		t.Fatal(err)
	}
	o := NewHighRiskOverlay()
	if warning, err := o.SetDeviceRisk("dev", "high"); err != nil || !warning {
		t.Fatal(warning, err)
	}
	p := &riskErasurePersister{}
	o.SetPersister(p)
	for _, input := range [][2]string{{"", "high"}, {"dev", "invalid"}} {
		if _, err := o.SetDeviceRisk(input[0], input[1]); err == nil {
			t.Fatal("invalid accepted")
		}
	}
	if p.writes != 0 {
		t.Fatal("invalid input wrote")
	}
	for _, severity := range []string{"none", "low", ""} {
		if _, err := o.SetDeviceRisk("dev", severity); err != nil {
			t.Fatal(err)
		}
	}
	if len(o.Snapshot()) != 0 {
		t.Fatal("clear aliases retained mark")
	}
}
