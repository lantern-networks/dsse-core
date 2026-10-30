package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestRearmSteeringOrdersAndRollsBackPartialPreparation(t *testing.T) {
	for _, fail := range []string{"", "quic", "dns", "wfp"} {
		t.Run(fail, func(t *testing.T) {
			var got []string
			step := func(name string) func() error {
				return func() error {
					got = append(got, name)
					if name == fail {
						return errors.New("failed")
					}
					return nil
				}
			}
			err := rearmSteering(step("quic"), func() error { got = append(got, "undo-quic"); return nil },
				step("dns"), func() error { got = append(got, "undo-dns"); return nil }, step("wfp"),
				func() error { got = append(got, "undo-wfp"); return nil })
			want := []string{"quic", "dns", "wfp"}
			switch fail {
			case "quic":
				want = []string{"quic", "undo-dns", "undo-quic"}
			case "dns":
				want = []string{"quic", "dns", "undo-dns", "undo-quic"}
			case "wfp":
				want = []string{"quic", "dns", "wfp", "undo-wfp", "undo-dns", "undo-quic"}
			}
			if (err != nil) != (fail != "") || !reflect.DeepEqual(got, want) {
				t.Fatalf("fail=%q err=%v steps=%v want=%v", fail, err, got, want)
			}
		})
	}
}

func TestRearmSteeringReportsQUICCleanupFailure(t *testing.T) {
	applyErr := errors.New("DNS takeover failed")
	cleanupErr := errors.New("QUIC rule remains")
	err := rearmSteering(func() error { return nil }, func() error { return cleanupErr },
		func() error { return applyErr }, nil, nil, nil)
	if !errors.Is(err, applyErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("partial rearm must report both the trigger and QUIC cleanup failure: %v", err)
	}
}

func TestRearmSteeringReportsFailedDNSRecovery(t *testing.T) {
	applyErr := errors.New("DNS takeover failed")
	rollbackErr := errors.New("native DNS recovery failed")
	err := rearmSteering(nil, nil, func() error { return applyErr },
		func() error { return rollbackErr }, nil, nil)
	if !errors.Is(err, applyErr) || !errors.Is(err, rollbackErr) {
		t.Fatalf("both the apply and native-recovery errors must be reported: %v", err)
	}
}

func TestRearmSteeringReportsUnverifiedWFPRollback(t *testing.T) {
	setErr := errors.New("WFP SET failed")
	clearErr := errors.New("WFP CLEAR unverified")
	err := rearmSteering(nil, nil, nil, nil, func() error { return setErr },
		func() error { return clearErr })
	if !errors.Is(err, setErr) || !errors.Is(err, clearErr) {
		t.Fatalf("both WFP SET and rollback failures must be reported: %v", err)
	}
}
