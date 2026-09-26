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

func TestLicenseProductionStartup(t *testing.T) {
	module, _ := filepath.Abs("../..")
	for _, kind := range []string{"malformed", "empty", "missing-serial"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			seedCertPinStartup(t, dir)
			path := filepath.Join(dir, "license.json")
			raw := map[string][]byte{"malformed": []byte(`{"allocations":`), "empty": {}, "missing-serial": []byte(`{"schema_version":"dsse.vendor_license_state.v1"}`)}[kind]
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a", "-license-store", path}
			argBytes, _ := json.Marshal(args)
			argPath := filepath.Join(dir, "args.json")
			if err := os.WriteFile(argPath, argBytes, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCertPinProductionStartupKeepsAuthoredIntent$")
			cmd.Env = append(os.Environ(), "DSSE_CERTPIN_STARTUP_ARGS="+argPath)
			out, err := cmd.CombinedOutput()
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), "setup vendor license store:") {
				t.Fatalf("startup not refused at license gate: %v %s", err, out)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatal("startup altered input")
			}
		})
	}
}
