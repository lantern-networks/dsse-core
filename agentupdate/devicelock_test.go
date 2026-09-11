package agentupdate

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// ★ The race this exists for, made deterministic: two holders of the same device, one lock.
func TestOnlyOneHolderAtATime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.lock")

	first, err := LockDevice(path)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	defer first.Release()

	// A SECOND PROCESS, not a second call: flock and LockFileEx are per-process, so an in-process second
	// attempt can succeed on some platforms and would test nothing about the case that matters — a daemon pass
	// and an operator's rollback running side by side.
	probe := exec.Command(os.Args[0], "-test.run=TestLockProbeHelper")
	probe.Env = append(os.Environ(), "DSSE_LOCK_PROBE="+path)
	out, perr := probe.CombinedOutput()
	if perr == nil {
		t.Fatalf("a second process took a lock the first was holding: %s", out)
	}

	// Once released, the next holder gets it — a lock that outlives its holder is a device that can never be
	// updated again.
	first.Release()
	second, err := LockDevice(path)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	second.Release()
}

// TestLockProbeHelper is the child half of the test above. It fails when it CANNOT take the lock, which is
// what the parent asserts.
func TestLockProbeHelper(t *testing.T) {
	path := os.Getenv("DSSE_LOCK_PROBE")
	if path == "" {
		t.Skip("not the probe")
	}
	l, err := LockDevice(path)
	if errors.Is(err, ErrLocked) {
		t.Fatalf("held elsewhere, as expected")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	l.Release()
}

// Release must be safe on a lock that was never taken, so callers can defer it before checking the error.
func TestReleasingANilOrDoubleLockIsSafe(t *testing.T) {
	var nilLock *DeviceLock
	nilLock.Release()

	l, err := LockDevice(filepath.Join(t.TempDir(), "update.lock"))
	if err != nil {
		t.Fatal(err)
	}
	l.Release()
	l.Release()
}
