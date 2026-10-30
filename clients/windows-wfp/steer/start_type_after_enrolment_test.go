package main

import "testing"

func TestEnrolmentOnlyPromotesDemandStart(t *testing.T) {
	for _, tc := range []struct {
		name    string
		start   uint32
		promote bool
	}{
		{"boot", 0, false},
		{"system", 1, false},
		{"auto", 2, false},
		{"demand", 3, true},
		{"disabled", 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldRaiseOwnStartType(tc.start); got != tc.promote {
				t.Fatalf("start type %d: promote=%v, want %v", tc.start, got, tc.promote)
			}
		})
	}
}
