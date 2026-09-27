package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/revocation"
)

type fakeRiskMarker struct{ marks map[string]string }

func (f *fakeRiskMarker) RaiseDeviceRisk(deviceID, severity string) (revocation.AutomaticRiskResult, error) {
	if f.marks == nil {
		f.marks = map[string]string{}
	}
	f.marks[deviceID] = severity
	return revocation.AutomaticRiskResult{Severity: severity, Applied: true, Changed: true, Persistence: "saved"}, nil
}

func rec(types []string, dest, class string) dlpDetectionRecord {
	return dlpDetectionRecord{types: types, destination: dest, instanceClass: class}
}

// The operator's worked example: >=2 distinct types to the SAME destination >=10 times in 5 min -> high.
func TestDeviceRiskCompositeWorkedExample(t *testing.T) {
	m := &fakeRiskMarker{}
	a := newDLPDeviceRiskAggregator(m)
	cond := []model.DLPDeviceRiskCondition{{MinCount: 10, MinDistinctTypes: 2, SameDestination: true, WindowSeconds: 300, Severity: "high"}}
	base := time.Unix(1_000_000, 0)

	// 9 detections of ONE type to a host — count high but only ONE type → does NOT trip (diversity filters the FP).
	for i := 0; i < 9; i++ {
		if sev := a.Record("dev", rec([]string{"credit_card"}, "telemetry.example", ""), cond, base.Add(time.Duration(i)*time.Second)); sev.ConditionSeverity != "" {
			t.Fatalf("single-type burst must not trip (FP): tripped at i=%d", i)
		}
	}
	if len(m.marks) != 0 {
		t.Fatal("device marked despite single-type (FP) traffic")
	}
	// Add a 10th detection that ALSO brings a 2nd distinct type to the same destination → now 10 records, 2 types → trips.
	if sev := a.Record("dev", rec([]string{"my_number"}, "telemetry.example", ""), cond, base.Add(10*time.Second)); sev.ConditionSeverity != "high" {
		t.Fatalf("10 detections of 2 distinct types to one destination should trip high, got %+v", sev)
	}
	if m.marks["dev"] != "high" {
		t.Fatalf("device should be marked high, got %q", m.marks["dev"])
	}
}

// Diversity across DIFFERENT destinations does not satisfy same_destination.
func TestDeviceRiskSameDestinationRequired(t *testing.T) {
	m := &fakeRiskMarker{}
	a := newDLPDeviceRiskAggregator(m)
	cond := []model.DLPDeviceRiskCondition{{MinCount: 3, MinDistinctTypes: 2, SameDestination: true, WindowSeconds: 300, Severity: "high"}}
	base := time.Unix(2_000_000, 0)
	a.Record("d", rec([]string{"my_number"}, "a.example", ""), cond, base)
	a.Record("d", rec([]string{"credit_card"}, "b.example", ""), cond, base.Add(time.Second))
	if sev := a.Record("d", rec([]string{"email"}, "c.example", ""), cond, base.Add(2*time.Second)); sev.ConditionSeverity != "" {
		t.Fatal("spread across destinations must not trip a same_destination condition")
	}
}

// Detections outside the window are pruned from the evaluation.
func TestDeviceRiskWindowBurst(t *testing.T) {
	m := &fakeRiskMarker{}
	a := newDLPDeviceRiskAggregator(m)
	cond := []model.DLPDeviceRiskCondition{{MinCount: 2, MinDistinctTypes: 2, SameDestination: true, WindowSeconds: 60, Severity: "high"}}
	base := time.Unix(3_000_000, 0)
	a.Record("d", rec([]string{"my_number"}, "x", ""), cond, base)
	// Second, but 2 minutes later — the first is outside the 60s window, so only 1 in-window → no trip.
	if sev := a.Record("d", rec([]string{"credit_card"}, "x", ""), cond, base.Add(2*time.Minute)); sev.ConditionSeverity != "" {
		t.Fatal("a slow trickle across the window boundary must not trip a burst condition")
	}
	// A third within 60s of the second → 2 in-window, 2 types → trips.
	if sev := a.Record("d", rec([]string{"my_number"}, "x", ""), cond, base.Add(2*time.Minute+30*time.Second)); sev.ConditionSeverity != "high" {
		t.Fatalf("a real burst should trip, got %+v", sev)
	}
}

// destination_class=personal only counts detections to personal/outside-org destinations.
func TestDeviceRiskDestinationClass(t *testing.T) {
	m := &fakeRiskMarker{}
	a := newDLPDeviceRiskAggregator(m)
	cond := []model.DLPDeviceRiskCondition{{MinCount: 2, MinDistinctTypes: 2, SameDestination: true, WindowSeconds: 300, DestinationClass: "personal", Severity: "high"}}
	base := time.Unix(4_000_000, 0)
	// Two diverse detections but to a CORPORATE instance → excluded → no trip.
	a.Record("d", rec([]string{"my_number"}, "drive", "corporate"), cond, base)
	if sev := a.Record("d", rec([]string{"credit_card"}, "drive", "corporate"), cond, base.Add(time.Second)); sev.ConditionSeverity != "" {
		t.Fatal("corporate-instance detections must be excluded by destination_class=personal")
	}
	// Same to a PERSONAL instance → counted → trips.
	a.Record("d", rec([]string{"my_number"}, "gdrive-personal", "personal"), cond, base.Add(2*time.Second))
	if sev := a.Record("d", rec([]string{"credit_card"}, "gdrive-personal", "personal"), cond, base.Add(3*time.Second)); sev.ConditionSeverity != "high" {
		t.Fatalf("personal-instance diverse burst should trip, got %+v", sev)
	}
}

func TestDeviceRiskNoConditionsOrEmptyDevice(t *testing.T) {
	m := &fakeRiskMarker{}
	a := newDLPDeviceRiskAggregator(m)
	cond := []model.DLPDeviceRiskCondition{{MinCount: 1, MinDistinctTypes: 1, Severity: "high"}}
	if a.Record("", rec([]string{"my_number"}, "x", ""), cond, time.Unix(5_000_000, 0)).ConditionSeverity != "" {
		t.Fatal("empty device id must be a no-op")
	}
	if a.Record("d", rec([]string{"my_number"}, "x", ""), nil, time.Unix(5_000_000, 0)).ConditionSeverity != "" {
		t.Fatal("no conditions must be a no-op")
	}
	newDLPDeviceRiskAggregator(nil).Record("d", rec([]string{"my_number"}, "x", ""), cond, time.Unix(5_000_000, 0)) // nil marker no panic
}

func TestDeviceRiskStrongestConditionAndExistingMark(t *testing.T) {
	for _, order := range [][]string{{"medium", "critical", "high"}, {"critical", "high", "medium"}} {
		o := revocation.NewHighRiskOverlay()
		a := newDLPDeviceRiskAggregator(o)
		conditions := []model.DLPDeviceRiskCondition{}
		for _, severity := range order {
			conditions = append(conditions, model.DLPDeviceRiskCondition{MinCount: 1, Severity: severity})
		}
		r := a.Record("d", rec([]string{"email"}, "upload.invalid", ""), conditions, time.Now())
		if r.ConditionSeverity != "critical" || !r.Applied || r.AutomaticRiskResult.Severity != "critical" {
			t.Fatal(r)
		}
		r = a.Record("d", rec([]string{"email"}, "upload.invalid", ""), conditions[:0:0], time.Now())
		if r.ConditionSeverity != "" || r.Applied {
			t.Fatal(r)
		}
		r = a.Record("d", rec([]string{"email"}, "upload.invalid", ""), []model.DLPDeviceRiskCondition{{MinCount: 1, Severity: "high"}}, time.Now())
		if r.ConditionSeverity != "high" || !r.Applied || r.Changed || r.AutomaticRiskResult.Severity != "critical" {
			t.Fatal(r)
		}
	}
	a := newDLPDeviceRiskAggregator(nil)
	r := a.Record("d", rec([]string{"email"}, "upload.invalid", ""), []model.DLPDeviceRiskCondition{{MinCount: 1}}, time.Now())
	if r.ConditionSeverity != "high" || r.Applied || r.Err != revocation.ErrRiskUnavailable {
		t.Fatal(r)
	}
}

func TestDeviceRiskSeverityNormalizationAndInvalidOutcome(t *testing.T) {
	for _, value := range []string{" HIGH ", "unsupported"} {
		o := revocation.NewHighRiskOverlay()
		a := newDLPDeviceRiskAggregator(o)
		r := a.Record("d", rec([]string{"email"}, "upload.invalid", ""), []model.DLPDeviceRiskCondition{{MinCount: 1, Severity: value}}, time.Now())
		if value == " HIGH " {
			if r.ConditionSeverity != "high" || !r.Applied || r.Err != nil {
				t.Fatal(r)
			}
		} else {
			if r.ConditionSeverity != "unsupported" || r.Applied || r.Err == nil {
				t.Fatal("invalid signal incorrectly acknowledged", r)
			}
		}
	}
}
