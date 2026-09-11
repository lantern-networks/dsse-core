package agentupdate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// devicelock — only one thing at a time may be deciding what this device installs.
//
// ★ WHY THE JOURNAL IS NOT ENOUGH (2026-08-11, from a review, and I had been doing exactly this all day). The
// journal is written atomically, which prevents a torn file and prevents nothing else. The macOS LaunchDaemon
// runs a pass every thirty minutes; an operator runs `--rollback` at the same moment; both read the same idle
// journal, both decide they may proceed, both write a transition, and both launch an installer. One machine,
// two installers, and a journal describing whichever wrote last.
//
// Atomicity answers "is the file readable". Exclusion answers "is anyone else acting", and nothing was asking.
//
// THE LOCK IS ON THE DEVICE, not on the journal path, and it is held for the WHOLE decision — from reading the
// journal to launching the installer — because every shorter window has the same race inside it. It is
// released when the process exits, including when it is killed: an updater that dies mid-install must not
// leave a device that can never be updated again, so the lock is advisory and process-scoped rather than a
// file that has to be cleaned up.
//
// A caller that cannot take it does NOT wait. Queueing behind a thirty-minute daemon pass would leave an
// operator's rollback sitting on a terminal with no output, and the honest answer is available immediately:
// something else is deciding right now, try again.

// ErrLocked is what every entry point returns when another process holds the device's update lock.
var ErrLocked = errors.New("another update or rollback is in progress on this device")

// DeviceLock is a held lock. Release is idempotent.
type DeviceLock struct {
	f      *os.File
	closed bool
}

// Release drops the lock. Safe to call twice, and safe to call on a nil lock so callers can defer it before
// checking the error.
func (l *DeviceLock) Release() {
	if l == nil || l.closed || l.f == nil {
		return
	}
	l.closed = true
	_ = unlockFile(l.f)
	_ = l.f.Close()
}

// LockDevice takes the device-wide update lock, or returns ErrLocked immediately if someone else holds it.
//
// path is a lock file the caller owns; it is created if missing and never removed — removing it is how two
// processes end up locking two different inodes and both proceeding.
func LockDevice(path string) (*DeviceLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create the lock directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the update lock %s: %w", path, err)
	}
	if err := tryLockFile(f); err != nil {
		f.Close()
		if errors.Is(err, ErrLocked) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("take the update lock %s: %w", path, err)
	}
	return &DeviceLock{f: f}, nil
}
