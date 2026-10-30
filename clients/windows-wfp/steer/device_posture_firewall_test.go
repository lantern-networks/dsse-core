package main

import "testing"

func TestFirewallStatusRequiresUnambiguousProfiles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		states [3]int8
		want   string
	}{
		{"all enabled", [3]int8{1, 1, 1}, "on"},
		{"all disabled", [3]int8{0, 0, 0}, "off"},
		{"one disabled", [3]int8{1, 1, 0}, ""},
		{"one enabled", [3]int8{0, 0, 1}, ""},
		{"one unreadable with enabled", [3]int8{1, 1, -1}, ""},
		{"one unreadable with disabled", [3]int8{0, 0, -1}, ""},
		{"all unreadable", [3]int8{-1, -1, -1}, ""},
		{"unexpected setting", [3]int8{1, 1, 2}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := firewallStatusFromProfiles(tc.states); got != tc.want {
				t.Fatalf("firewallStatusFromProfiles(%v) = %q, want %q", tc.states, got, tc.want)
			}
		})
	}
}
