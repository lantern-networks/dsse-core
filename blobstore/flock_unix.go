//go:build !windows

package blobstore

import (
	"fmt"
	"os"
	"syscall"
)

// withFileLock runs fn while holding an EXCLUSIVE advisory lock on a lock file beside path.
//
// ★ COMPARING AND THEN WRITING IS NOT A COMPARE-AND-SWAP (2026-08-12, twenty-fourth review). The guard read
// the file, checked the bytes were the ones it last saw, and then wrote — three steps with nothing holding
// them together across processes. Two Edges could both read the same old contents, both find them unchanged,
// and both write; the second erased the first, which is the lost update the check was added to stop. A mutex
// inside one process cannot see the other one.
//
// An advisory lock CAN, and it is the kernel's: it is released when the descriptor closes, including when the
// process dies, so there is no stale-lock recovery to get wrong — the objection that usually makes a lockfile
// worse than the problem does not apply.
//
// It is a SEPARATE .lock file rather than the store itself, because the store is replaced by rename: a lock
// held on the old inode would not be seen by whoever opened the new one.
func withFileLock(path string, fn func() error) error {
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open %q: %w", lockPath, err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock %q: %w", lockPath, err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
