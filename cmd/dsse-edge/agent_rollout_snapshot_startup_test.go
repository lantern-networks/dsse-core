package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentrollout"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

func TestRolloutSnapshotProductionStartup(t *testing.T) {
	n := 11
	plan := agentrollout.AgentRolloutPlan{Frozen: true, DesiredVersion: "0.3.1", Intent: "rollout", Reason: "PRIVATE_SAVED_REASON", Waves: &agentrollout.WaveSchedule{Waves: []agentrollout.RolloutWave{{Group: "Pilot", Priority: 9}}, DefaultDelayDays: &n}, Window: &agentupdate.PlanWindow{LocalStart: "01:00", LocalEnd: "05:00", RequireACPower: true}}
	valid, _ := json.Marshal(map[string]agentrollout.AgentRolloutPlan{"startup-own": plan, "startup-other": {Frozen: true, Reason: "other hold"}})
	prepare := func(name string, data []byte, missing bool) (string, string) {
		t.Helper()
		dir := t.TempDir()
		if root := os.Getenv("DSSE_ROLLOUT_RESTORE_EVIDENCE"); root != "" {
			dir = filepath.Join(root, "main", name)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
		}
		seedCertPinStartup(t, dir)
		path := filepath.Join(dir, "rollout.json")
		if !missing {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return dir, path
	}
	for _, tc := range []struct {
		name    string
		data    []byte
		missing bool
		want    agentrollout.AgentRolloutPlan
	}{
		{"valid", valid, false, plan}, {"explicit-empty", []byte(`{}`), false, agentrollout.AgentRolloutPlan{}}, {"first-boot", nil, true, agentrollout.AgentRolloutPlan{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := prepare(tc.name, tc.data, tc.missing)
			for i := 0; i < 2; i++ {
				base, stop := startCertPinMain(t, dir, false, "-agent-rollout-store", path)
				var feed struct {
					Tenant string                        `json:"tenant_id"`
					Plan   agentrollout.AgentRolloutPlan `json:"plan"`
				}
				certPinStartupGet(t, base, "/admin/agent-rollout", &feed)
				stop()
				if feed.Tenant != "startup-own" || !reflect.DeepEqual(feed.Plan, tc.want) {
					t.Fatalf("wrong restored plan: %+v", feed)
				}
				if tc.missing {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatal("startup created absent state")
					}
				} else {
					after, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(after, tc.data) {
						t.Fatal("startup changed state")
					}
				}
			}
		})
	}
	bad := map[string][]byte{
		"zero-file": {}, "null": []byte(`null`), "null-plan": []byte(`{"startup-own":null}`), "missing-halt": []byte(`{"startup-own":{"reason":"PRIVATE_SAVED_REASON"}}`),
		"duplicate-halt": []byte(`{"startup-own":{"frozen":true,"frozen":false}}`), "alias-halt": []byte(`{"startup-own":{"Frozen":true}}`),
		"bad-window":       bytes.Replace(valid, []byte(`"require_idle_minutes":0`), []byte(`"require_idle_minutes":-1`), 1),
		"duplicate-tenant": []byte(`{"startup-own":{"frozen":true},"startup-own":{"frozen":false}}`),
	}
	module, _ := filepath.Abs("../..")
	for name, data := range bad {
		t.Run(name, func(t *testing.T) {
			dir, path := prepare(name, data, false)
			args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a", "-agent-rollout-store", path}
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
			if e := os.WriteFile(filepath.Join(dir, "refused.log"), out, 0600); e != nil {
				t.Fatal(e)
			}
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), "agent rollout store: read the shared agent rollout store: invalid agent rollout snapshot") {
				t.Fatalf("startup not refused: %v deadline=%v output=%s", err, ctx.Err(), out)
			}
			if bytes.Contains(out, []byte("PRIVATE_SAVED_REASON")) {
				t.Fatal("saved reason disclosed")
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(after, data) {
				t.Fatal("rejected startup rewrote snapshot")
			}
		})
	}
	t.Logf("actual main: 3 accepted twice, %d refused", len(bad))
}
