package certreload

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/durablefile"
)

func TestPairRecoveryFailureRetainsMaterialAndLiveCertificate(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	serial := writeSelfSigned(t, cp, kp, "old")
	r, err := NewReloadableCert(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := os.ReadFile(cp)
	k, _ := os.ReadFile(kp)
	_, _, jp, _ := pairPaths(cp, kp)
	j := pairJournal{Schema: pairJournalSchema, State: "prepared", CertPath: cp, KeyPath: kp, Cert: c, Key: k}
	if err := writePairJournal(jp, j); err != nil {
		t.Fatal(err)
	}
	writeSelfSigned(t, cp, kp, "new")
	os.Remove(kp)
	os.Mkdir(kp, 0700)
	if err := r.Reload(); err == nil {
		t.Fatal("recovery must refuse blocked destination")
	}
	if servedSerial(t, r).Cmp(serial) != 0 {
		t.Fatal("failed recovery changed live")
	}
	got, err := readPairJournal(jp, cp, kp)
	if err != nil || got == nil || got.State != "prepared" {
		t.Fatal("recovery material lost")
	}
	os.Remove(kp)
	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	if servedSerial(t, r).Cmp(serial) != 0 {
		t.Fatal("recovery served wrong pair")
	}
	raw, _ := os.ReadFile(jp)
	if bytes.Contains(raw, []byte("cert\":")) || bytes.Contains(raw, []byte("key\":")) {
		t.Fatal("completed journal retained key")
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{kp, jp} {
			st, _ := os.Stat(p)
			if st.Mode().Perm() != 0600 {
				t.Fatal("private file permission")
			}
		}
	}
}
func TestPairMalformedRecoveryCannotOverwriteOrHideFailure(t *testing.T) {
	for _, bad := range []string{`{`, `{"schema":"unknown"}`} {
		t.Run(bad, func(t *testing.T) {
			dir := t.TempDir()
			cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
			writeSelfSigned(t, cp, kp, "old")
			r, _ := NewReloadableCert(cp, kp)
			c, _ := os.ReadFile(cp)
			_, _, jp, _ := pairPaths(cp, kp)
			os.WriteFile(jp, []byte(bad), 0600)
			if err := r.Reload(); err == nil {
				t.Fatal("bad journal ignored")
			}
			called := false
			if err := WithPairUpdate(cp, kp, func() error { called = true; return nil }); err == nil || called {
				t.Fatal("bad journal overwritten")
			}
			got, _ := os.ReadFile(cp)
			if !bytes.Equal(got, c) {
				t.Fatal("material changed")
			}
			raw, _ := os.ReadFile(jp)
			if string(raw) != bad {
				t.Fatal("recovery evidence changed")
			}
		})
	}
}
func TestPairReloadWaitsForUpdateAndFailurePreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	writeSelfSigned(t, cp, kp, "old")
	r, _ := NewReloadableCert(cp, kp)
	c, _ := os.ReadFile(cp)
	k, _ := os.ReadFile(kp)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- WithPairUpdate(cp, kp, func() error { close(entered); <-release; return durablefile.Write(cp, c, 0600) })
	}()
	<-entered
	reloaded := make(chan error, 1)
	go func() { reloaded <- r.Reload() }()
	select {
	case err := <-reloaded:
		t.Fatalf("reload raced update: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-reloaded; err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		os.Chmod(kp, 0400)
	}
	if err := WithPairUpdate(cp, kp, func() error { return errors.New("refused before replacement") }); err == nil {
		t.Fatal("refusal lost")
	}
	got, _ := os.ReadFile(kp)
	if !bytes.Equal(got, k) {
		t.Fatal("unchanged key changed")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(kp)
		if st.Mode().Perm() != 0400 {
			t.Fatal("refusal weakened key permission")
		}
	}
}
