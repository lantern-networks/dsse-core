//go:build windows

package agentupdate

import (
	"os"

	"golang.org/x/sys/windows"
)

// LockFileEx with LOCKFILE_FAIL_IMMEDIATELY: the same contract as flock on the other side — exclusive,
// non-blocking, and released by the kernel when the handle closes or the process dies.
func tryLockFile(f *os.File) error {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
	if err == nil {
		return nil
	}
	if err == windows.ERROR_LOCK_VIOLATION || err == windows.ERROR_IO_PENDING {
		return ErrLocked
	}
	return err
}

func unlockFile(f *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped)
}
