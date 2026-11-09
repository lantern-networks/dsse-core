//go:build !windows

package main

import (
	"syscall"
	"testing"
)

// withPrivateUmask narrows the process umask so a test can prove the installer writes private files private
// on its own, not by the shell's accident. The returned function restores it; it is also restored at cleanup.
func withPrivateUmask(t *testing.T) func() {
	t.Helper()
	previous := syscall.Umask(0o077)
	restore := func() { syscall.Umask(previous) }
	t.Cleanup(restore)
	return restore
}
