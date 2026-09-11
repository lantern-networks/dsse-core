//go:build darwin || linux

package main

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestInstallWithPrivateUmaskKeepsContainerInputsReadable(t *testing.T) {
	if os.Getenv("DSSE_TEST_PRIVATE_UMASK_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestInstallWithPrivateUmaskKeepsContainerInputsReadable$")
		cmd.Env = append(os.Environ(), "DSSE_TEST_PRIVATE_UMASK_CHILD=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("private-umask installation: %v\n%s", err, out)
		}
		return
	}
	// Isolate the process-wide umask from the rest of the test suite.
	syscall.Umask(0o077)
	dir := t.TempDir()
	if err := run(dir, "install.example.test", "Installer Test", 1, false); err != nil {
		t.Fatal(err)
	}
	want := map[string]os.FileMode{
		"haproxy.cfg": 0o644, "haproxy-edge.cfg": 0o644,
		"haproxy-postgres.cfg": 0o644, storeCAFile: 0o644,
		"clickhouse-init": 0o755, "deployment.env": 0o600,
		"management.key": 0o600, storeMemberKeyFile: 0o600,
		authorityDirName: 0o700,
		filepath.Join(authorityDirName, storeCAKeyFile): 0o600,
	}
	entries, err := os.ReadDir(filepath.Join(dir, "clickhouse-init"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("ClickHouse initialization files missing: %v", err)
	}
	for _, e := range entries {
		want[filepath.Join("clickhouse-init", e.Name())] = 0o644
	}
	for name, mode := range want {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Error(err)
		} else if info.Mode().Perm() != mode {
			t.Errorf("%s: mode %04o, want %04o", name, info.Mode().Perm(), mode)
		}
	}
	// Packing for another region must preserve these modes through staging and
	// the archive, including when the operator protects new files with umask 077.
	plan, err := LoadPlan(writePlan(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := applyPlanToFoundingMachine(plan, dir); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "cp-b.tar.gz")
	if err := carryPlanMachine(plan, dir, dest, "cp-b"); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		h.Name = strings.TrimSuffix(h.Name, "/")
		if h.Name == authorityDirName || strings.HasPrefix(h.Name, authorityDirName+"/") {
			t.Errorf("authority material included in carry: %s", h.Name)
		}
		if mode, ok := want[h.Name]; ok {
			seen[h.Name] = true
			if os.FileMode(h.Mode).Perm() != mode {
				t.Errorf("carried %s: mode %04o, want %04o", h.Name, h.Mode, mode)
			}
		}
	}
	for _, name := range []string{storeCAFile, storeMemberKeyFile, "deployment.env", "clickhouse-init", filepath.Join("clickhouse-init", entries[0].Name())} {
		if !seen[name] {
			t.Errorf("required carry input missing: %s", name)
		}
	}
}
