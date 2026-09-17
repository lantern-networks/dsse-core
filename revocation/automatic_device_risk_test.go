package revocation

import (
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"reflect"
	"testing"
)

func TestAutomaticDeviceRiskSaveRetry(t *testing.T) {
	bridge := errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	for _, tc := range []struct {
		name   string
		err    error
		retain bool
		status string
	}{
		{"atomic", nil, true, "saved"}, {"in_place", blobstore.ErrSavedWithoutAtomicity, true, "saved_non_atomic"},
		{"no_write", errors.New("private"), false, "unconfirmed"}, {"write_error", errors.New("private"), true, "unconfirmed"},
		{"flush_lost", blobstore.ErrDurabilityUnconfirmed, false, "unconfirmed"}, {"flush_retained", blobstore.ErrDurabilityUnconfirmed, true, "unconfirmed"},
		{"bridge_lost", bridge, false, "unconfirmed"}, {"bridge_retained", bridge, true, "unconfirmed"},
		{"wrapped_lost", fmt.Errorf("private: %w", bridge), false, "unconfirmed"}, {"wrapped_retained", fmt.Errorf("private: %w", bridge), true, "unconfirmed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &riskErasurePersister{}
			o := NewHighRiskOverlay()
			if err := o.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			o.Mark("Target", "medium")
			o.Mark("target", "critical")
			o.Mark("foreign", "high")
			if _, err := o.SetUserRisk(UserRisk{TenantID: "foreign", ID: "Target", Severity: "critical"}); err != nil {
				t.Fatal(err)
			}
			gen, writes, users := o.ConfigGeneration(), p.writes, o.UserSnapshot()
			p.err, p.retain = tc.err, tc.retain
			result, err := o.RaiseDeviceRisk(" Target ", "high")
			failed := tc.status == "unconfirmed"
			if (err != nil) != failed || result.Persistence != tc.status || !result.Applied || !result.Changed || result.Severity != "high" {
				t.Fatalf("%+v %v", result, err)
			}
			if o.Snapshot()["Target"] != "high" || o.ConfigGeneration() != gen+1 || p.writes != writes+1 {
				t.Fatal("raise was not published/saved")
			}
			result, err = o.RaiseDeviceRisk("Target", "high")
			expected := tc.status
			if !failed {
				expected = "not_attempted"
			}
			if (err != nil) != failed || result.Changed || !result.Applied || result.Persistence != expected {
				t.Fatalf("repeat: %+v %v", result, err)
			}
			wantedWrites := writes + 1
			if failed {
				wantedWrites++
			}
			if p.writes != wantedWrites {
				t.Fatal("repeat save count")
			}
			p.err = nil
			result, err = o.RaiseDeviceRisk("Target", "medium") // lower requested signal must retain HIGH, including on retry
			if err != nil || result.Changed || !result.Applied || result.Severity != "high" {
				t.Fatalf("lower/retry: %+v %v", result, err)
			}
			if failed && result.Persistence != "saved" {
				t.Fatal("failed snapshot not retried")
			}
			savedWrites := p.writes
			result, err = o.RaiseDeviceRisk("Target", "high")
			if err != nil || result.Persistence != "not_attempted" || p.writes != savedWrites || o.ConfigGeneration() != gen+1 {
				t.Fatal("stable hit rewrites snapshot or generation")
			}
			reload := NewHighRiskOverlay()
			if err := reload.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(o.Snapshot(), reload.Snapshot()) || !reflect.DeepEqual(users, reload.UserSnapshot()) {
				t.Fatal("restart/foreign/case/user mismatch")
			}
		})
	}
}
func TestAutomaticDeviceRiskUnavailableAndRecovery(t *testing.T) {
	for _, data := range []string{"{", `{"schema_version":"high_risk_overlay_state.v1","devices":{"d":"high"}}`} {
		t.Run(data, func(t *testing.T) {
			p := &riskErasurePersister{riskFlushPersister: riskFlushPersister{data: []byte(data)}}
			o := NewHighRiskOverlay()
			_ = o.SetPersister(p)
			before := o.Snapshot()
			gen := o.ConfigGeneration()
			r, e := o.RaiseDeviceRisk("d", "critical")
			if e != ErrRiskUnavailable || r.Applied || r.Changed || r.Persistence != "not_attempted" || p.writes != 0 || !reflect.DeepEqual(before, o.Snapshot()) || gen != o.ConfigGeneration() {
				t.Fatal(r, e)
			}
			p.data = []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{}}`)
			if e := o.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			r, e = o.RaiseDeviceRisk("d", "high")
			if e != nil || r.Persistence != "saved" {
				t.Fatal(r, e)
			}
		})
	}
	var absent *HighRiskOverlay
	r, e := absent.RaiseDeviceRisk("d", "high")
	if e != ErrRiskUnavailable || r.Applied {
		t.Fatal(r, e)
	}
}
func TestAutomaticDeviceRiskVolatileAttachAndSharedSave(t *testing.T) {
	o := NewHighRiskOverlay()
	for i := 0; i < 2; i++ {
		r, e := o.RaiseDeviceRisk("d", "high")
		if e != nil || r.Persistence != "volatile" || r.Changed != (i == 0) {
			t.Fatal(r, e)
		}
	}
	p := &riskErasurePersister{}
	if e := o.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	r, e := o.RaiseDeviceRisk("d", "high")
	if e != nil || r.Persistence != "saved" || r.Changed || p.writes != 1 {
		t.Fatal(r, e)
	}
	p.err = errors.New("save")
	_, _ = o.RaiseDeviceRisk("d", "critical")
	p.err = nil
	if _, e := o.SetUserRisk(UserRisk{TenantID: "other", ID: "user", Severity: "high"}); e != nil {
		t.Fatal(e)
	}
	writes := p.writes
	r, e = o.RaiseDeviceRisk("d", "critical")
	if e != nil || r.Persistence != "not_attempted" || p.writes != writes {
		t.Fatal("confirmed shared save was retried", r, e)
	}
	for _, input := range [][2]string{{"", "high"}, {"d", "none"}, {"d", "bad"}} {
		r, e = o.RaiseDeviceRisk(input[0], input[1])
		if e == nil || r.Applied || p.writes != writes {
			t.Fatal("invalid accepted", r, e)
		}
	}
}
func TestAutomaticDeviceRiskPendingReadsAndQueuedAdminClear(t *testing.T) {
	o := NewHighRiskOverlay()
	p := newAdmissionGatedStore(t)
	p.err = errors.New("delayed")
	if e := o.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	done := admissionAsync(func() error { _, e := o.RaiseDeviceRisk("target", "high"); return e })
	admissionWithin(t, p.entered)
	state := admissionWithin(t, admissionAsync(func() riskReadState { return readRiskState(o) }))
	if state.Devices["target"] != "high" {
		t.Fatal("pending escalation absent")
	}
	clear := admissionAsync(func() error { _, e := o.SetDeviceRisk("target", "none"); return e })
	select {
	case <-done:
		t.Fatal("early result")
	default:
	}
	select {
	case <-clear:
		t.Fatal("writer overtook save")
	default:
	}
	p.release()
	if admissionWithin(t, done) != ErrRiskSave || admissionWithin(t, clear) != ErrRiskSave {
		t.Fatal("lost failure")
	}
	if o.Snapshot()["target"] != "high" {
		t.Fatal("failed clear lost automatic protection")
	}
}
