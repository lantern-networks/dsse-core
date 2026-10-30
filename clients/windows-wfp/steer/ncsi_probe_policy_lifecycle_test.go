package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

type fakeNCSIPolicy struct {
	value      uint32
	exists     bool
	readErr    error
	writeErr   error
	deleteErr  error
	restartErr error
	writes     int
	deletes    int
	restarts   int
}

func (f *fakeNCSIPolicy) ops(path string) ncsiPolicyOps {
	return ncsiPolicyOps{
		backupPath: path,
		read: func() (string, bool, error) {
			if f.readErr != nil {
				return "", false, f.readErr
			}
			if !f.exists {
				return "", false, nil
			}
			return formatNCSITestValue(f.value), true, nil
		},
		write: func(v uint32) error {
			f.writes++
			if f.writeErr != nil {
				return f.writeErr
			}
			f.value, f.exists = v, true
			return nil
		},
		delete: func() error {
			f.deletes++
			if f.deleteErr != nil {
				return f.deleteErr
			}
			f.exists = false
			return nil
		},
		restart: func(string) error {
			f.restarts++
			return f.restartErr
		},
	}
}

func formatNCSITestValue(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

func TestNCSISuppressRestorePreservesPriorPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    fakeNCSIPolicy
		want string
	}{
		{"absent", fakeNCSIPolicy{}, "absent"},
		{"operator_value", fakeNCSIPolicy{value: 0, exists: true}, "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "backup")
			f := tc.f
			ops := f.ops(path)
			prior, err := ncsiSuppressWith(ops)
			if err != nil || prior != tc.want || !f.exists || f.value != 1 {
				t.Fatalf("suppress prior=%q err=%v state=%+v", prior, err, f)
			}
			if b, err := os.ReadFile(path); err != nil || string(b) != tc.want {
				t.Fatalf("backup=%q err=%v", b, err)
			}
			// Re-arm after a service restart must keep the true original value, not snapshot its own '=1'.
			if prior, err := ncsiSuppressWith(ops); err != nil || prior != tc.want {
				t.Fatalf("re-arm prior=%q err=%v", prior, err)
			}
			prior, err = ncsiRestoreWith(ops)
			if err != nil || prior != tc.want || f.exists != tc.f.exists || (f.exists && f.value != tc.f.value) {
				t.Fatalf("restore prior=%q err=%v state=%+v", prior, err, f)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("restored backup still present: %v", err)
			}
		})
	}
}

func TestNCSISuppressRequiresSavedSnapshot(t *testing.T) {
	f := &fakeNCSIPolicy{value: 0, exists: true}
	path := filepath.Join(t.TempDir(), "missing-dir", "backup")
	if _, err := ncsiSuppressWith(f.ops(path)); err == nil || f.writes != 0 || f.restarts != 0 {
		t.Fatalf("backup failure changed policy: err=%v state=%+v", err, f)
	}
	path = filepath.Join(t.TempDir(), "backup")
	f.readErr = errors.New("registry read failed")
	if _, err := ncsiSuppressWith(f.ops(path)); err == nil || f.writes != 0 {
		t.Fatalf("read failure changed policy: err=%v state=%+v", err, f)
	}
}

func TestNCSIBackupPublicationNeverReplacesOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup")
	if err := ncsiSaveBackup(path, "0"); err != nil {
		t.Fatal(err)
	}
	if err := ncsiSaveBackup(path, "1"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second publication should refuse existing backup: %v", err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "0" {
		t.Fatalf("first backup replaced: %q %v", b, err)
	}
	for attempt := 0; attempt < 20; attempt++ {
		path := filepath.Join(t.TempDir(), "raced-backup")
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, prior := range []string{"0", "1"} {
			go func(prior string) {
				<-start
				results <- ncsiSaveBackup(path, prior)
			}(prior)
		}
		close(start)
		a, b := <-results, <-results
		if (a == nil) == (b == nil) {
			t.Fatalf("expected exactly one publisher, got %v / %v", a, b)
		}
		if a != nil && !errors.Is(a, os.ErrExist) || b != nil && !errors.Is(b, os.ErrExist) {
			t.Fatalf("unexpected publication errors: %v / %v", a, b)
		}
		if saved, err := os.ReadFile(path); err != nil || (string(saved) != "0" && string(saved) != "1") {
			t.Fatalf("invalid raced backup %q: %v", saved, err)
		}
	}
}

func TestNCSIRestoreKeepsBackupUntilVerified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup")
	if err := os.WriteFile(path, []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeNCSIPolicy{value: 1, exists: true, writeErr: errors.New("registry write failed")}
	if _, err := ncsiRestoreWith(f.ops(path)); err == nil {
		t.Fatal("registry restore error accepted")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "0" {
		t.Fatalf("backup lost after failed restore: %q %v", b, err)
	}
	f.writeErr = nil
	f.readErr = errors.New("readback failed")
	if _, err := ncsiRestoreWith(f.ops(path)); err == nil {
		t.Fatal("unverified restore accepted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("backup lost before readback: %v", err)
	}
	f.readErr = nil
	f.restartErr = errors.New("service restart failed")
	if _, err := ncsiRestoreWith(f.ops(path)); err == nil {
		t.Fatal("service restart error accepted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("backup lost before service restart: %v", err)
	}
	f.restartErr = nil
	if _, err := ncsiRestoreWith(f.ops(path)); err != nil || f.value != 0 {
		t.Fatalf("recovery failed: err=%v state=%+v", err, f)
	}
}

func TestNCSIRestoreDoesNotGuessMissingOrCorruptBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup")
	f := &fakeNCSIPolicy{value: 1, exists: true}
	if prior, err := ncsiRestoreWith(f.ops(path)); prior != "" || err != nil || f.writes != 0 || f.deletes != 0 {
		t.Fatalf("missing backup changed policy: prior=%q err=%v state=%+v", prior, err, f)
	}
	for _, corrupt := range []string{"", "arbitrary", "4294967296"} {
		if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ncsiRestoreWith(f.ops(path)); err == nil || f.writes != 0 || f.deletes != 0 {
			t.Fatalf("corrupt backup %q changed policy: err=%v state=%+v", corrupt, err, f)
		}
	}
}
