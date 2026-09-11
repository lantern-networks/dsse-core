//go:build windows

package main

import "testing"

// ★★★ A read-only mode must not spend a one-time approval (2026-08-30, measured by spending one).
// --mode bypass-observe lists which processes an exclusion matches. It enrolled: the token was consumed by a
// command that inspects nothing but the process table, and the device key was DPAPI-wrapped at the context
// the diagnostic ran in, so the service could never open it. modeTakesTheNetworkPath already draws the line.
func TestTheModesThatMustNotEnrol(t *testing.T) {
	for _, m := range []string{"bypass-observe", "print-config", "recover", "watchdog", "enroll"} {
		if modeTakesTheNetworkPath(m) {
			t.Errorf("%q takes the network path, so it would enrol", m)
		}
	}
	for _, m := range []string{"redirect", "observe", ""} {
		if !modeTakesTheNetworkPath(m) {
			t.Errorf("%q does NOT take the network path, so it would refuse to enrol when it should", m)
		}
	}
}
