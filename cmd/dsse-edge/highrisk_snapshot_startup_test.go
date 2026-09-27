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

func TestRiskSnapshotProductionStartup(t *testing.T) {
	prepare := func(name string, data []byte, missing, directory bool) (string, string) {
		t.Helper()
		dir := t.TempDir()
		if root := os.Getenv("DSSE_RISK_RESTORE_EVIDENCE"); root != "" {
			dir = filepath.Join(root, "after-main", name)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
		}
		seedCertPinStartup(t, dir)
		path := filepath.Join(dir, "risk.json")
		if directory {
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		} else if !missing {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return dir, path
	}
	valid := `{"schema_version":"high_risk_overlay_state.v2","devices":{"Owned":"high","owned":"medium"}}`
	for _, tc := range []struct {
		name, data string
		missing    bool
		count      int
	}{
		{"case-sensitive-devices", valid, false, 2},
		{"empty-v1", `{"schema_version":"high_risk_overlay_state.v1","devices":{}}`, false, 0},
		{"empty-v2", `{"schema_version":"high_risk_overlay_state.v2","devices":{},"users":{}}`, false, 0},
		{"first-boot", "", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := prepare(tc.name, []byte(tc.data), tc.missing, false)
			for restart := 0; restart < 2; restart++ {
				base, stop := startCertPinMain(t, dir, false, "-high-risk-store", path)
				var feed struct {
					HighRisk   map[string]string `json:"high_risk"`
					Withheld   int               `json:"withheld_unattributable"`
					EntityType string            `json:"entity_type"`
				}
				certPinStartupGet(t, base, "/admin/risk-signals", &feed)
				stop()
				// No enrolled inventory was provided: the API must withhold these device names.
				if len(feed.HighRisk) != 0 || feed.Withheld != tc.count || feed.EntityType != "device" {
					t.Fatalf("wrong risk restoration: %+v", feed)
				}
				if tc.missing {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatal("missing snapshot was created")
					}
				} else {
					b, e := os.ReadFile(path)
					if e != nil || !bytes.Equal(b, []byte(tc.data)) {
						t.Fatal("startup rewrote risk snapshot")
					}
				}
			}
		})
	}
	bad := map[string][]byte{
		"zero-file": {}, "null": []byte(`null`), "truncated": []byte(`{"devices":{"PRIVATE_SNAPSHOT_VALUE":`),
		"unknown-schema":    []byte(strings.Replace(valid, "high_risk_overlay_state.v2", "PRIVATE_SNAPSHOT_VALUE", 1)),
		"missing-devices":   []byte(`{"schema_version":"high_risk_overlay_state.v2"}`),
		"null-devices":      []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":null}`),
		"duplicate-devices": []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{"Owned":"high"},"devices":{}}`),
		"duplicate-device":  []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{"Owned":"high","Owned":"medium"}}`),
		"duplicate-schema":  []byte(`{"schema_version":"unknown","schema_version":"high_risk_overlay_state.v2","devices":{}}`),
		"null-users":        []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{},"users":null}`),
		"alias":             []byte(strings.Replace(valid, "devices", "Devices", 1)),
		"read-error":        nil,
	}
	module, _ := filepath.Abs("../..")
	for name, data := range bad {
		t.Run(name, func(t *testing.T) {
			dir, path := prepare(name, data, false, name == "read-error")
			args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a", "-high-risk-store", path}
			b, _ := json.Marshal(args)
			argPath := filepath.Join(dir, "args.json")
			if err := os.WriteFile(argPath, b, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCertPinProductionStartupKeepsAuthoredIntent$")
			cmd.Env = append(os.Environ(), "DSSE_CERTPIN_STARTUP_ARGS="+argPath)
			out, err := cmd.CombinedOutput()
			if e := os.WriteFile(filepath.Join(dir, "refused-startup.log"), out, 0600); e != nil {
				t.Fatal(e)
			}
			want := "load high-risk store: invalid risk snapshot"
			if name == "read-error" {
				want = "load high-risk store: cannot read risk snapshot"
			}
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), want) {
				t.Fatalf("startup not refused: error=%v deadline=%v output=%s", err, ctx.Err(), out)
			}
			if bytes.Contains(out, []byte("PRIVATE_SNAPSHOT_VALUE")) {
				t.Fatal("snapshot content disclosed")
			}
			if name != "read-error" {
				after, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(after, data) {
					t.Fatal("rejected startup rewrote snapshot")
				}
			}
		})
	}
	t.Logf("actual main: 4 accepted, %d refused snapshots", len(bad))
}
