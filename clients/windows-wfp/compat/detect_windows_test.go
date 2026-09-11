//go:build windows

package compat

import "testing"

// TestDetect_RealMachine runs the real registry probes on the build/test box and exercises Evaluate both ways.
// It does not assert specific hardware facts (those vary by machine) — it proves Detect() compiles + runs on a
// real Windows machine without panicking, that the native arch is resolved, and it logs the facts + gate verdict
// so a run on this box is a visible end-to-end check.
func TestDetect_RealMachine(t *testing.T) {
	f := Detect()
	t.Logf("detected: arch=%s sMode=%v secureBoot=%v hvci=%v build=%d (%s)",
		f.Arch, f.SMode, f.SecureBoot, f.HVCI, f.WindowsBuild, f.DisplayVersion)

	if f.Arch == ArchUnknown {
		t.Errorf("native arch should resolve on a real machine (got Unknown)")
	}
	if f.WindowsBuild <= 0 {
		t.Errorf("Windows build should resolve on a real machine (got %d)", f.WindowsBuild)
	}

	prod := Evaluate(f, true)
	test := Evaluate(f, false)
	t.Logf("gate (attestation-signed): %s", prod.Summary())
	for _, w := range prod.Warnings {
		t.Logf("  warn: %s", w)
	}
	t.Logf("gate (test-signed):        %s", test.Summary())
	for _, b := range test.Blocks {
		t.Logf("  block: %s", b)
	}
}
