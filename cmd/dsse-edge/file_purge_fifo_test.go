//go:build !windows

package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/logs"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Block a real append while it owns the cached file handle. Reading one byte
// proves Write has started; the remaining megabyte exceeds the FIFO capacity.
func blockTenantLogAppend(t *testing.T, w *logs.Writer, tenant string) func() {
	t.Helper()
	name := "stalled.log.jsonl"
	path := filepath.Join(w.Dir(), "tenants", tenant, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	reader, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK, 0600)
	if err != nil {
		t.Fatal(err)
	}
	w.SetTenantPartitionedFiles(name)
	done := make(chan error, 1)
	go func() {
		done <- w.Append(name, map[string]any{"tenant_id": tenant, "data": strings.Repeat("x", 1<<20)})
	}()
	var once sync.Once
	release := func() {
		once.Do(func() {
			unix.Close(reader)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("append did not end after reader closed")
			}
		})
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		var b [1]byte
		n, _ := unix.Read(reader, b[:])
		if n == 1 {
			return release
		}
		time.Sleep(time.Millisecond)
	}
	release()
	t.Fatal("append did not enter actual Write")
	return nil
}

func TestFilePurgeBlockedFilesystemReturnsUnknown(t *testing.T) {
	root := t.TempDir()
	w, err := logs.NewWriter(filepath.Join(root, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	release := blockTenantLogAppend(t, w, "target")
	defer release()
	h := newLegalHoldStore(blobstore.FilePersister{Path: filepath.Join(root, "holds.json")})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	done := make(chan adminTenantPurgeResult, 1)
	go func() {
		done <- purgeAdminTenantData(ctx, "test", "target", nil, w, nil, nil, nil, nil, "", nil, nil, adminTenantExtraStores{}, h, time.Now())
	}()
	select {
	case result := <-done:
		if result.Complete || result.Remaining.Clean() {
			t.Fatal("unconfirmed filesystem counted clean", result)
		}
		found := false
		for _, r := range result.Remaining.Stores {
			if r.Store == "log_files" && r.Count == -1 {
				found = true
			}
		}
		if !found {
			t.Fatal("missing unknown count", result)
		}
	case <-time.After(time.Second):
		release()
		<-done
		t.Fatal("purge caller blocked in filesystem or repeated footprint read")
	}
	release()
	wait, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err = h.writeMu.LockContext(wait); err != nil {
		t.Fatal(err)
	}
	h.writeMu.Unlock()
	if !newLegalHoldStore(h.persister).IsHeld("target") {
		t.Fatal("marker missing after failed erasure")
	}
	if _, err = os.Stat(filepath.Join(w.Dir(), "tenants", "target", "stalled.log.jsonl")); err != nil {
		t.Fatal("late close proceeded to deletion", err)
	}
}
