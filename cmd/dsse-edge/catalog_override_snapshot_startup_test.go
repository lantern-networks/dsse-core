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

	"github.com/lantern-networks/dsse-core/knownbypass"
)

func TestCatalogOverrideSnapshotProductionStartup(t *testing.T) {
	valid := `{"startup-own":{"github_asset_cdn":{"entry_id":"github_asset_cdn","mode":"force_inspect","updated_at":"2026-09-17T00:00:00Z"}},"startup-other":{"apple_time":{"entry_id":"apple_time","mode":"disabled"}}}`
	prepare := func(data []byte) (string, string) {
		t.Helper()
		dir := t.TempDir()
		seedCertPinStartup(t, dir)
		path := filepath.Join(dir, "overrides.json")
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
		return dir, path
	}
	for _, data := range [][]byte{[]byte(valid), []byte(strings.Replace(valid, `,"updated_at":"2026-09-17T00:00:00Z"`, "", 1)), []byte(`{}`)} {
		dir, path := prepare(data)
		base, stop := startCertPinMain(t, dir, false, "-predefined-catalog-override-store", path)
		var view struct {
			Overrides []knownbypass.Override `json:"overrides"`
		}
		certPinStartupGet(t, base, "/admin/predefined-catalog", &view)
		want := "inspect"
		if bytes.Equal(data, []byte(`{}`)) {
			want = "bypass"
			if len(view.Overrides) != 0 {
				t.Fatal("empty snapshot retained overrides")
			}
		} else if len(view.Overrides) != 1 || view.Overrides[0].EntryID != "github_asset_cdn" {
			t.Fatal("wrong restored identity", view)
		}
		var decision effectivePolicyResponse
		certPinStartupGet(t, base, "/admin/effective-policy?destination=github.githubassets.com", &decision)
		if decision.Inspection.Decision != want {
			t.Fatal("restored override not applied", decision.Inspection)
		}
		certPinStartupGet(t, base, "/admin/effective-policy?destination=time.apple.com", &decision)
		if decision.Inspection.Decision != "bypass" {
			t.Fatal("foreign override affected own tenant", decision.Inspection)
		}
		stop()
		after, _ := os.ReadFile(path)
		if !bytes.Equal(after, data) {
			t.Fatal("startup rewrote saved history")
		}
	}
	cases := map[string][]byte{
		"empty-file": nil, "null": []byte(`null`), "null-tenant": []byte(`{"startup-own":null}`),
		"wrong-key":    []byte(strings.Replace(valid, `"startup-own":{"github_asset_cdn":`, `"startup-own":{"PRIVATE_SNAPSHOT_VALUE":`, 1)),
		"invalid-mode": []byte(strings.Replace(valid, `"force_inspect"`, `"PRIVATE_SNAPSHOT_VALUE"`, 1)),
		"alias":        []byte(strings.Replace(valid, `"entry_id"`, `"Entry_ID"`, 1)),
		"duplicate":    []byte(`{"startup-own":{},"startup-own":{}}`),
		"unknown":      []byte(strings.Replace(valid, `"updated_at"`, `"PRIVATE_SNAPSHOT_VALUE"`, 1)),
		"timestamp":    []byte(strings.Replace(valid, `2026-09-17T00:00:00Z`, `PRIVATE_SNAPSHOT_VALUE`, 1)),
	}
	module, _ := filepath.Abs("../..")
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			dir, path := prepare(data)
			args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a", "-predefined-catalog-override-store", path}
			b, _ := json.Marshal(args)
			argsPath := filepath.Join(dir, "args.json")
			if e := os.WriteFile(argsPath, b, 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCertPinProductionStartupKeepsAuthoredIntent$")
			cmd.Env = append(os.Environ(), "DSSE_CERTPIN_STARTUP_ARGS="+argsPath)
			out, err := cmd.CombinedOutput()
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), "predefined-catalog override store: invalid catalog override snapshot") {
				t.Fatalf("bad startup err=%v deadline=%v output=%s", err, ctx.Err(), out)
			}
			if bytes.Contains(out, []byte("PRIVATE_SNAPSHOT_VALUE")) {
				t.Fatal("saved data in startup error")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(after, data) {
				t.Fatal("failed startup rewrote snapshot")
			}
		})
	}
	t.Logf("main: 3 accepted snapshots, %d rejected snapshots", len(cases))
}
