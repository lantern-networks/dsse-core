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

	"github.com/lantern-networks/dsse-core/policycandidate"
)

func TestCandidateSnapshotProductionStartup(t *testing.T) {
	for _, empty := range []bool{false, true} {
		dir := t.TempDir()
		seedCertPinStartup(t, dir)
		path := filepath.Join(dir, "candidates.json")
		if empty {
			if e := os.WriteFile(path, []byte(`{}`), 0600); e != nil {
				t.Fatal(e)
			}
		}
		before, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		base, stop := startCertPinMain(t, dir, false)
		var got policycandidate.ListResponse
		certPinStartupGet(t, base, "/admin/policy-candidates", &got)
		stop()
		want := 6
		if empty {
			want = 0
		}
		if len(got.Candidates) != want {
			t.Fatalf("empty=%v: count %d", empty, len(got.Candidates))
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("main changed candidate history")
		}
	}
	invalid := []string{"", `null`, `{"startup-own":{}} {}`, `{"startup-own":{},"startup-own":{}}`}
	for _, field := range []string{"tenant_id", "status", "unexpected"} {
		dir := t.TempDir()
		seedCertPinStartup(t, dir)
		raw, e := os.ReadFile(filepath.Join(dir, "candidates.json"))
		if e != nil {
			t.Fatal(e)
		}
		var snapshot map[string]map[string]map[string]any
		json.Unmarshal(raw, &snapshot)
		for _, c := range snapshot["startup-own"] {
			c[field] = "PRIVATE_INVALID"
			break
		}
		b, _ := json.Marshal(snapshot)
		invalid = append(invalid, string(b))
	}
	module, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	for i, data := range invalid {
		dir := t.TempDir()
		seedCertPinStartup(t, dir)
		path := filepath.Join(dir, "candidates.json")
		if e := os.WriteFile(path, []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
		args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a", "-policy-candidate-store", path}
		raw, _ := json.Marshal(args)
		argsPath := filepath.Join(dir, "args.json")
		os.WriteFile(argsPath, raw, 0600)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCertPinProductionStartupKeepsAuthoredIntent$")
		cmd.Env = append(os.Environ(), "DSSE_CERTPIN_STARTUP_ARGS="+argsPath)
		out, err := cmd.CombinedOutput()
		deadline := ctx.Err()
		cancel()
		if err == nil || deadline != nil || !strings.Contains(string(out), "policy candidate store: invalid policy candidate snapshot") {
			t.Fatalf("case %d: err=%v deadline=%v out=%s", i, err, deadline, out)
		}
		if bytes.Contains(out, []byte("PRIVATE_INVALID")) {
			t.Fatal("startup logged saved candidate contents")
		}
		after, _ := os.ReadFile(path)
		if string(after) != data {
			t.Fatal("failed startup changed input")
		}
	}
	t.Logf("main: 2 accepted snapshots, %d rejected snapshots", len(invalid))
}
