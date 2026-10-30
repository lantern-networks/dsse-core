package main

import (
	"errors"
	"strings"
	"testing"
)

func TestDriverRemovalRequiresObservedStop(t *testing.T) {
	const (
		stopped = uint32(1)
		pending = uint32(3)
		running = uint32(4)
	)
	for _, tc := range []struct {
		name     string
		initial  uint32
		final    uint32
		queryErr error
		stopErr  error
		waitErr  error
		wantStop bool
		wantWait bool
		wantErr  bool
	}{
		{name: "already stopped", initial: stopped, final: stopped},
		{name: "running then stopped", initial: running, final: stopped, wantStop: true, wantWait: true},
		{name: "stop already pending", initial: pending, final: stopped, wantWait: true},
		{name: "stop refused", initial: running, stopErr: errors.New("refused"), wantStop: true, wantErr: true},
		{name: "stop timeout", initial: running, waitErr: errors.New("timeout"), wantStop: true, wantWait: true, wantErr: true},
		{name: "still running after wait", initial: running, final: running, wantStop: true, wantWait: true, wantErr: true},
		{name: "query unavailable", queryErr: errors.New("unavailable"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queries, stops, waits := 0, 0, 0
			err := confirmStoppedBeforeDelete(func() (uint32, error) {
				queries++
				if tc.queryErr != nil {
					return 0, tc.queryErr
				}
				if queries == 1 {
					return tc.initial, nil
				}
				return tc.final, nil
			}, func() error {
				stops++
				return tc.stopErr
			}, func() error {
				waits++
				return tc.waitErr
			}, stopped, pending)
			if (err != nil) != tc.wantErr || (stops != 0) != tc.wantStop || (waits != 0) != tc.wantWait {
				t.Fatalf("err=%v stops=%d waits=%d, want error=%v stop=%v wait=%v", err, stops, waits, tc.wantErr, tc.wantStop, tc.wantWait)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "driver") {
				t.Fatalf("removal refusal does not identify the driver: %v", err)
			}
		})
	}
}

func TestDriverRemovalRequiresObservedAbsence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		absentAt  int
		probeErr  error
		wantError bool
	}{
		{"already absent", 1, nil, false},
		{"pending then absent", 3, nil, false},
		{"pending timeout", 0, nil, true},
		{"access denied", 0, errors.New("denied"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probes, waits := 0, 0
			err := confirmDriverAbsent(func() (bool, error) { probes++; return probes == tc.absentAt, tc.probeErr },
				func() bool { waits++; return waits < 4 })
			if (err != nil) != tc.wantError {
				t.Fatalf("%v", err)
			}
			if tc.probeErr != nil && waits != 0 {
				t.Fatal("query error treated as pending")
			}
		})
	}
}
