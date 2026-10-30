package logs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func waitForLogCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for log writer state")
}

func TestCloseDoesNotHoldWriterLockWhileWaitingForFile(t *testing.T) {
	w, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lf, err := w.fileFor("audit.log.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lf.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- w.Close() }()
	// Close must detach its handles before waiting for a writer's file mutex.
	// A rotating writer already holds that mutex and needs Writer.mu next.
	detached := false
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if w.mu.TryLock() {
			detached = len(w.openFiles) == 0
			w.mu.Unlock()
			if detached {
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	lf.mu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not complete")
	}
	if !detached {
		t.Fatal("Close holds Writer.mu while blocked on file.mu; concurrent rotation deadlocks")
	}
	lf.mu.Lock()
	closed := lf.closed
	lf.mu.Unlock()
	if !closed {
		t.Error("detached handle not marked closed for in-flight writers")
	}
	if err := w.Append("audit.log.jsonl", map[string]any{"event": "after-close"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// A detached old handle must finish its rotation before another append handle
// can open the same path. Otherwise that new descriptor keeps pointing at the
// inode the old handle renames to .1, and subsequent writes disappear from the
// active log (or overwrite the rotated backup on the next rotation).
func TestCloseAndRotationDoNotOpenTwoHandlesForOnePath(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.SetRotation(1, 2, false)
	const name = "access.log.jsonl"
	lf, err := w.fileFor(name)
	if err != nil {
		t.Fatal(err)
	}
	lf.mu.Lock()
	first := make(chan error, 1)
	go func() { first <- w.Append(name, map[string]any{"event": "first"}) }()
	waitForLogCondition(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.useClock >= 2
	})
	closed := make(chan error, 1)
	go func() { closed <- w.Close() }()
	// The old implementation detached immediately and permitted a second fd to
	// open before first could rotate. The corrected implementation keeps that
	// path gated until the old append finishes.
	detached := false
	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		detached = w.openFiles[name] == nil
		w.mu.Unlock()
		if detached {
			break
		}
		time.Sleep(time.Millisecond)
	}
	var second chan error
	var next *logFile
	if detached {
		next, err = w.fileFor(name)
		if err != nil {
			lf.mu.Unlock()
			t.Fatal(err)
		}
		next.mu.Lock()
		w.mu.Lock()
		stamp := w.useClock
		w.mu.Unlock()
		second = make(chan error, 1)
		go func() { second <- w.Append(name, map[string]any{"event": "second"}) }()
		// Ensure the second Append has taken the new descriptor before the old
		// one rotates; it will wait on next.mu before writing.
		waitForLogCondition(t, func() bool {
			w.mu.Lock()
			defer w.mu.Unlock()
			return w.useClock > stamp
		})
	}
	lf.mu.Unlock()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if detached {
		next.mu.Unlock()
	} else {
		second = make(chan error, 1)
		go func() { second <- w.Append(name, map[string]any{"event": "second"}) }()
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	newest, err := os.ReadFile(filepath.Join(dir, name+".1"))
	if err != nil {
		t.Fatal(err)
	}
	older, err := os.ReadFile(filepath.Join(dir, name+".2"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(older, []byte(`"event":"first"`)) ||
		!bytes.Contains(newest, []byte(`"event":"second"`)) ||
		bytes.Contains(older, []byte(`"event":"second"`)) {
		t.Fatalf("rotation wrote through an obsolete handle: newest=%q older=%q", newest, older)
	}
}

func TestCloseTenantWaitsForItsAppendBeforeDetaching(t *testing.T) {
	w, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.SetTenantPartitionedFiles("access.log.jsonl")
	const tenant = "tenant-a"
	clean := tenantPartitionPath(tenant, "access.log.jsonl")
	lf, err := w.fileFor(clean)
	if err != nil {
		t.Fatal(err)
	}
	lf.mu.Lock()
	appended := make(chan error, 1)
	go func() { appended <- w.Append("access.log.jsonl", map[string]any{"tenant_id": tenant}) }()
	waitForLogCondition(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.useClock >= 2
	})
	closed := make(chan error, 1)
	go func() { closed <- w.CloseTenant(tenant) }()
	time.Sleep(25 * time.Millisecond)
	w.mu.Lock()
	detachedEarly := w.openFiles[clean] == nil
	w.mu.Unlock()
	lf.mu.Unlock()
	if err := <-appended; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if detachedEarly {
		t.Fatal("CloseTenant detached a handle while its append could still rotate")
	}
	if err := w.Append("access.log.jsonl", map[string]any{"tenant_id": tenant, "event": "after-close"}); err != nil {
		t.Fatal(err)
	}
}

func TestLRUEvictionDoesNotReopenPathDuringOldAppend(t *testing.T) {
	w, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.SetMaxOpenFiles(1)
	const name = "access.log.jsonl"
	lf, err := w.fileFor(name)
	if err != nil {
		t.Fatal(err)
	}
	lf.mu.Lock()
	first := make(chan error, 1)
	go func() { first <- w.Append(name, map[string]any{"event": "first"}) }()
	waitForLogCondition(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.useClock >= 2
	})
	evicted := make(chan error, 1)
	go func() { _, err := w.fileFor("other.log.jsonl"); evicted <- err }()
	waitForLogCondition(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.openFiles[name] == nil && w.openFiles["other.log.jsonl"] != nil
	})
	second := make(chan error, 1)
	go func() { second <- w.Append(name, map[string]any{"event": "second"}) }()
	time.Sleep(25 * time.Millisecond)
	w.mu.Lock()
	reopenedEarly := w.openFiles[name] != nil
	w.mu.Unlock()
	lf.mu.Unlock()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-evicted; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if reopenedEarly {
		t.Fatal("LRU allowed a second handle for a path before the old append completed")
	}
}
