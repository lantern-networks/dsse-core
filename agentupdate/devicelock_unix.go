//go:build !windows

package agentupdate

import (
	"os"
	"syscall"
)

// flock, non-blocking. It is released by the kernel when the process exits or the descriptor closes, which is
// the property that matters: an updater killed mid-install must not leave a device nobody can update again.
func tryLockFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if err == syscall.EWOULDBLOCK {
			return ErrLocked
		}
		return err
	}
	return nil
}

func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
