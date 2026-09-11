//go:build !windows

package main

import "fmt"

// defaultStepUpLauncher is a no-op stub on non-Windows builds (the steering agent only runs on Windows). It
// keeps `go build ./...` and the pure stepUpCoordinator tests green on Mac/CI, and logs so a mis-target on a
// non-Windows host is visible rather than silent.
func defaultStepUpLauncher(resource, portalURL string) {
	fmt.Printf("steer_stepup (no-op on non-windows) resource=%s url=%s\n", resource, portalURL)
}
