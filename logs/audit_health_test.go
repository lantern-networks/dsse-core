package logs

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAuditHealthPreservesFailuresAndSeparatesHooks(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	if w.AuditHealth().Status != "unknown" {
		t.Fatal("unobserved writer reported healthy")
	}
	// A directory at the target path forces a real primary file-open failure.
	path := filepath.Join(dir, "audit.log.jsonl")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := w.Append("audit.log.jsonl", map[string]any{"id": "failed"}); err == nil {
		t.Fatal("open succeeded")
	}
	h := w.AuditHealth()
	if h.Status != "degraded" || h.PrimaryFailures != 1 || h.LastPrimaryFailurePhase != "open" {
		t.Fatalf("failure invisible: %+v", h)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := w.Append("audit.log.jsonl", map[string]any{"id": "recovered"}); err != nil {
		t.Fatal(err)
	}
	h = w.AuditHealth()
	if h.Status != "degraded" || h.PrimaryFailures != 1 || h.PrimarySuccesses != 1 {
		t.Fatalf("success erased loss: %+v", h)
	}
	w.SetAppendHook(func(string, []byte) error { return errors.New("private-hook-location") })
	if err := w.Append("audit.log.jsonl", map[string]any{"id": "hook-failed"}); err == nil {
		t.Fatal("hook succeeded")
	}
	h = w.AuditHealth()
	if h.PrimarySuccesses != 2 || h.PrimaryFailures != 1 || h.HookFailures != 1 || h.LastPrimaryFailurePhase != "open" || h.LastHookFailureAt == "" {
		t.Fatalf("hook conflated with primary: %+v", h)
	}
	w.SetAppendHook(nil)
	if err := w.Append("audit.log.jsonl", make(chan int)); err == nil {
		t.Fatal("encoding unexpectedly succeeded")
	}
	if w.AuditHealth().LastPrimaryFailurePhase != "encode" {
		t.Fatal("encode failure absent")
	}
	// Other streams do not establish or erase audit health.
	attempts := w.AuditHealth().Attempts
	_ = w.Append("access.log.jsonl", map[string]any{"id": "other"})
	if w.AuditHealth().Attempts != attempts {
		t.Fatal("other stream changed audit health")
	}
	fresh, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if fresh.AuditHealth().Status != "unknown" {
		t.Fatal("new process inferred persistence history")
	}
	var absent *Writer
	if absent.AuditHealth().Status != "unavailable" {
		t.Fatal("missing writer reported healthy")
	}
}

func TestAuditHealthConcurrentSnapshots(t *testing.T) {
	w, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Append("audit.log.jsonl", map[string]any{"id": "concurrent"}); err != nil {
				t.Error(err)
			}
			_ = w.AuditHealth()
		}()
	}
	wg.Wait()
	h := w.AuditHealth()
	if h.Attempts != 20 || h.PrimarySuccesses != 20 || h.Status != "healthy" {
		t.Fatalf("lost observations: %+v", h)
	}
}

func TestAuditHealthReadDoesNotWaitForBlockedHook(t *testing.T) {
	w, err := NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	w.SetAppendHook(func(string, []byte) error { close(entered); <-release; return nil })
	go func() { done <- w.Append("audit.log.jsonl", map[string]any{"id": "blocked"}) }()
	<-entered
	read := make(chan AuditWriteHealth, 1)
	go func() { read <- w.AuditHealth() }()
	select {
	case <-read:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("health blocked behind append")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAuditHealthDistinguishesWriteAndRotationFailures(t *testing.T) {
	for _, phase := range []string{"write", "rotation"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			w, err := NewWriter(dir)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "write" {
				lf, err := w.fileFor("audit.log.jsonl")
				if err != nil {
					t.Fatal(err)
				}
				if err := lf.f.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				// A nonempty directory cannot be removed or replaced by a rotated file.
				backup := filepath.Join(dir, "audit.log.jsonl.1")
				if err := os.Mkdir(backup, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(backup, "keep"), []byte("test"), 0600); err != nil {
					t.Fatal(err)
				}
				w.SetRotation(1, 1, false)
			}
			if err := w.Append("audit.log.jsonl", map[string]any{"id": "test"}); err == nil {
				t.Fatal("expected failure")
			}
			h := w.AuditHealth()
			if h.PrimaryFailures != 1 || h.PrimarySuccesses != 0 || h.HookFailures != 0 || h.LastPrimaryFailurePhase != phase {
				t.Fatalf("wrong phase: %+v", h)
			}
		})
	}
}
