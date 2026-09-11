package main

import "testing"

// armBreakGlassForTest makes the shared -admin-token authenticate for the duration of one test.
//
// ★ NEEDED BECAUSE THE DEFAULT CHANGED, AND THAT IS THE POINT (the machine-credential separation, 2026-08-16). The token used to
// authenticate by virtue of being configured; it now needs -admin-token-break-glass-armed. Twelve tests went
// red on the flip, every one of them driving an admin route with the shared token — which is a fair measure
// of how ordinary the break-glass had become.
//
// Tests that are ABOUT the break-glass path arm it here and say so. Tests that merely used it as a convenient
// credential should move to a named one instead; this helper is not meant to make the flip invisible.
func armBreakGlassForTest(t *testing.T) {
	t.Helper()
	previousArmed, previousConfigured := adminBreakGlass.Armed, adminBreakGlass.Configured
	adminBreakGlass.Armed, adminBreakGlass.Configured = true, true
	t.Cleanup(func() {
		adminBreakGlass.Armed, adminBreakGlass.Configured = previousArmed, previousConfigured
	})
}
