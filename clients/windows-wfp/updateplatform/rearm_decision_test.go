package updateplatform

import "testing"

func TestServiceStartDoesNotProveUnknownDriverRestored(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		observed, known, armed, want bool
	}{
		{"confirmed unarmed", true, true, false, true},
		{"confirmed armed", true, true, true, false},
		{"unknown driver state", true, false, false, false},
		{"no observation", false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := serviceStartProvesRestoration(tc.observed, tc.known, tc.armed); got != tc.want {
				t.Fatalf("serviceStartProvesRestoration(%t,%t,%t)=%t, want %t",
					tc.observed, tc.known, tc.armed, got, tc.want)
			}
		})
	}
}
