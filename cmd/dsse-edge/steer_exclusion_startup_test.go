package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/steerexclusion"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSteerExclusionProductionStartup(t *testing.T) {
	row := steerexclusion.Policy{ID: "owned", TenantID: "startup-own", ScopeType: "tenant", Status: "active", ExcludedAppSigningIDs: []string{"com.example.tool"}}
	valid, _ := json.Marshal(map[string]any{"policies": []steerexclusion.Policy{row}})
	prepare := func(name string, data []byte, missing bool) (string, string) {
		t.Helper()
		dir := t.TempDir()
		if root := os.Getenv("DSSE_STEERING_RESTORE_EVIDENCE"); root != "" {
			dir = filepath.Join(root, "main", name)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
		}
		seedCertPinStartup(t, dir)
		path := filepath.Join(dir, "steer.json")
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
		count   int
	}{
		{"valid", valid, false, 1}, {"empty", []byte(`{"policies":[]}`), false, 0}, {"first-boot", nil, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := prepare(tc.name, tc.data, tc.missing)
			for i := 0; i < 2; i++ {
				base, stop := startCertPinMain(t, dir, false, "-steer-exclusion-store", path)
				var feed struct {
					Schema   string                  `json:"schema_version"`
					Policies []steerexclusion.Policy `json:"steer_exclusions"`
				}
				certPinStartupGet(t, base, "/admin/steer-exclusions", &feed)
				stop()
				if feed.Schema != steerexclusion.ListSchema || len(feed.Policies) != tc.count {
					t.Fatal("wrong restored set", feed)
				}
				if tc.missing {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatal("missing source rewritten")
					}
				} else {
					after, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(after, tc.data) {
						t.Fatal("startup changed source")
					}
				}
			}
		})
	}
	duplicate, _ := json.Marshal(map[string]any{"policies": []steerexclusion.Policy{row, row}})
	bad := map[string][]byte{
		"empty-file": {}, "null": []byte(`null`), "empty-object": []byte(`{}`),
		"null-array": []byte(`{"policies":null}`), "null-row": []byte(`{"policies":[null]}`),
		"duplicate-key": []byte(`{"policies":[],"policies":[]}`), "duplicate-row": duplicate,
		"bad-status": bytes.Replace(valid, []byte(`"active"`), []byte(`"unknown"`), 1),
	}
	module, _ := filepath.Abs("../..")
	for name, data := range bad {
		t.Run(name, func(t *testing.T) {
			dir, path := prepare(name, data, false)
			args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a", "-steer-exclusion-store", path}
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
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), "init steer exclusion store: load persisted steer exclusions: invalid steering exclusion snapshot") {
				t.Fatalf("startup not refused: %v %s", err, out)
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(after, data) {
				t.Fatal("rejected startup changed source")
			}
		})
	}
	t.Logf("actual main: 3 accepted twice, %d refused", len(bad))
}
