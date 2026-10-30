package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDNSPolicyProductionStartupRejectsUnreadableState(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		directory bool
	}{{"truncated", `{"deny":[`, false}, {"null", `null`, false}, {"directory", "", true}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			seedCertPinStartup(t, dir)
			path := filepath.Join(dir, "dns-policy.json")
			if tc.directory {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
					t.Fatal(err)
				}
			}
			module, _ := filepath.Abs("../..")
			args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-dns-policy-store", path}
			raw, _ := json.Marshal(args)
			argPath := filepath.Join(dir, "args.json")
			if err := os.WriteFile(argPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCertPinProductionStartupKeepsAuthoredIntent$")
			cmd.Env = append(os.Environ(), "DSSE_CERTPIN_STARTUP_ARGS="+argPath)
			out, err := cmd.CombinedOutput()
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), "DNS policy restore failed") {
				t.Fatalf("startup not refused before serving: err=%v deadline=%v output=%s", err, ctx.Err(), out)
			}
			if !tc.directory {
				got, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(got, []byte(tc.raw)) {
					t.Fatal("startup destroyed invalid operator state")
				}
			}
		})
	}
}
