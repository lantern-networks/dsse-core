//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// withDNSBackupLock serializes the live resolver manager and standalone recover
// across processes. Lock the sidecar rather than the backup itself: the backup
// is atomically replaced and removed while its lock must remain stable.
// Contention fails closed instead of letting two owners apply DNS concurrently.
func withDNSBackupLock(backup string, action func() error) error {
	f, err := os.OpenFile(backup+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open DNS backup lock: %w", err)
	}
	defer f.Close()
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped); err != nil {
		return fmt.Errorf("DNS backup is owned by another operation: %w", err)
	}
	defer windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped)
	return action()
}
