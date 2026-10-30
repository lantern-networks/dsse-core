package main

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestManifestInputIsOneUnambiguousObject(t *testing.T) {
	for _, raw := range []string{`{"version":"0.4.0"} {"version":"9.0.0"}`, `{"version":"0.4.0","version":"9.0.0"}`, `{"unknown_field":true}`} {
		if _, err := decodeManifest([]byte(raw)); err == nil {
			t.Errorf("ambiguous or unsupported manifest input accepted: %s", raw)
		}
	}
	m, err := decodeManifest([]byte("{\"version\":\"0.4.0\"}\n"))
	if err != nil || m.Version != "0.4.0" {
		t.Fatalf("ordinary JSON rejected: %+v %v", m, err)
	}
}

func TestSigningKeyCreationRefusesDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	link, target := filepath.Join(dir, "key"), filepath.Join(dir, "elsewhere")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := generateKey(link); err == nil {
		t.Error("key generation followed a pre-existing symlink")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("symlink target was modified")
	}
}

func TestConcurrentKeyCreationHasOneWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	start := make(chan struct{})
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if generateKey(path) == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent creators overwrote signing key: %d successes", successes.Load())
	}
	if _, err := loadSigner(path); err != nil {
		t.Fatalf("winning key is unusable: %v", err)
	}
}
