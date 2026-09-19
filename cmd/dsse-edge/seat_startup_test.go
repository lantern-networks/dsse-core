package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/seatallocation"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSeatAllocationProductionStartup(t *testing.T) {
	module, _ := filepath.Abs("../..")
	for _, kind := range []string{"malformed", "empty", "missing-map"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			seedCertPinStartup(t, dir)
			path := filepath.Join(dir, "seats.json")
			raw := map[string][]byte{"malformed": []byte(`{"allocations":`), "empty": {}, "missing-map": []byte(`{"schema_version":"dsse.seat_allocations.v1"}`)}[kind]
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a", "-seat-allocation-store", path}
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
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), "setup seat allocation store:") {
				t.Fatalf("startup not refused at seat gate: %v %s", err, out)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatal("startup altered input")
			}
		})
	}
	t.Run("first-boot-and-restart", func(t *testing.T) {
		dir := t.TempDir()
		seedCertPinStartup(t, dir)
		path := filepath.Join(dir, "seats.json")
		for i := 0; i < 2; i++ {
			base, stop := startCertPinMain(t, dir, false, "-seat-allocation-store", path)
			var licence struct {
				Tenants []struct {
					TenantID  string `json:"tenant_id"`
					Allocated int    `json:"allocated"`
				} `json:"tenants"`
			}
			certPinStartupGet(t, base, "/admin/license", &licence)
			stop()
			if i == 1 {
				found := false
				for _, v := range licence.Tenants {
					if v.TenantID == "startup-own" && v.Allocated == 8 {
						found = true
					}
				}
				if !found {
					t.Fatal("saved seats absent from restarted production API", licence)
				}
			} else {
				store := seatallocation.NewStore()
				if err := store.SetStateFile(path); err != nil {
					t.Fatal(err)
				}
				if _, err := store.Allocate(seatallocation.Policy{PoolSeats: 20}, "startup-own", 8, "operator", "", "now"); err != nil {
					t.Fatal(err)
				}
			}

		}
	})
}
