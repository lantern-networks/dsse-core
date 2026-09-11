//go:build !windows

package main

import "fmt"

// defaultWarnLauncher is a no-op stub off Windows (the WFP agent only runs on Windows; this keeps the package
// building on other platforms for tests/vet).
func defaultWarnLauncher(dest, service string) {
	fmt.Printf("steer_warn (no-op on non-windows) dest=%s service=%s\n", dest, service)
}
