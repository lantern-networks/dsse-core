//go:build windows

package main

import "testing"

// Windows has no umask; the test that narrows it runs the installer unchanged there.
func withPrivateUmask(t *testing.T) func() {
	t.Helper()
	return func() {}
}
