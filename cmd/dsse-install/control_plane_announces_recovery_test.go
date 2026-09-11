package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstalledControlPlaneReceivesRecoveryName(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "capture-arguments")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, disabled := range []bool{false, true} {
		if disabled {
			f, err := os.OpenFile(filepath.Join(dir, "deployment.env"), os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.WriteString("\nDSSE_RECOVERY_SNI=''\n")
			f.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("/bin/sh", filepath.Join(dir, "start-control-plane.sh"))
		cmd.Env = append(os.Environ(), "DSSE_EDGE_BINARY="+binary, "DSSE_POSTGRES_DSN=postgres://test.invalid/test", "DSSE_MIGRATION_DIR="+dir, "DSSE_CP_STATE_DIR="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("launcher failed: %v\n%s", err, out)
		}
		want := "-renewal-recovery-sni=recovery.dsse.example"
		if disabled {
			want = "-renewal-recovery-sni="
		}
		found := false
		for _, arg := range strings.Split(string(out), "\n") {
			if arg == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("generated control-plane command did not receive %q", want)
		}
	}
}
