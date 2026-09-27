package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMeshSnapshotProductionStartup(t *testing.T) {
	prepare := func(name string, data []byte, missing, directory bool) (string, string) {
		t.Helper()
		dir := t.TempDir()
		if root := os.Getenv("DSSE_MESH_RESTORE_EVIDENCE"); root != "" {
			dir = filepath.Join(root, "after-main", name)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
		}
		seedCertPinStartup(t, dir)
		path := filepath.Join(dir, "outbox.json")
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
	var requests atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(503) }))
	defer peer.Close()
	for _, tc := range []struct {
		name, data string
		missing    bool
		pending    int
	}{
		{"current", strings.ReplaceAll(meshRestoreValid, "https://peer.invalid/base", peer.URL), false, 1},
		{"legacy", `[{"region":"peer","url":"` + peer.URL + `","identity":"device"}]`, false, 1},
		{"empty-set", "[]", false, 0}, {"first-boot", "", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := prepare(tc.name, []byte(tc.data), tc.missing, false)
			for attempt := 0; attempt < 2; attempt++ {
				before := requests.Load()
				base, stop := startCertPinMain(t, dir, false, "-revocation-mesh-peers", "peer="+peer.URL, "-revocation-mesh-secret", "synthetic-mesh-restore", "-revocation-mesh-outbox-store", path)
				var feed revocationFeed
				certPinStartupGet(t, base, "/admin/revocations", &feed)
				if tc.pending > 0 {
					waitUntil(t, 3*time.Second, func() bool { return requests.Load() > before }, "restored queue must resume")
				}
				stop()
				if tc.missing {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatal("first boot created pending")
					}
				} else {
					data, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(data, []byte(tc.data)) {
						t.Fatal("startup rewrote pending")
					}
				}
				// Keep both startup logs when manual evidence is enabled.
				if data, err := os.ReadFile(filepath.Join(dir, "process.log")); err == nil {
					suffix := "first"
					if attempt == 1 {
						suffix = "second"
					}
					if err := os.WriteFile(filepath.Join(dir, suffix+"-startup.log"), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
	bad := invalidMeshSnapshots()
	bad["read-error"] = nil
	names := []string{"empty", "null", "null-entry", "partial", "duplicate-entry", "duplicate-field", "alias", "unknown", "null-required", "invalid-url", "read-error"}
	module, _ := filepath.Abs("../..")
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			data := bad[name]
			dir, path := prepare(name, data, false, name == "read-error")
			args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a", "-revocation-mesh-peers", "peer=" + peer.URL, "-revocation-mesh-secret", "synthetic-mesh-restore", "-revocation-mesh-outbox-store", path}
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
			want := "load revocation-mesh outbox: invalid revocation mesh outbox snapshot"
			if name == "read-error" {
				want = "load revocation-mesh outbox: cannot read revocation mesh outbox snapshot"
			}
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), want) {
				t.Fatalf("not refused: %v deadline=%v output=%s", err, ctx.Err(), out)
			}
			if bytes.Contains(out, []byte("PRIVATE_CONTENT")) {
				t.Fatal("snapshot contents disclosed")
			}
			if name != "read-error" {
				after, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(data, after) {
					t.Fatal("refused startup rewrote queue")
				}
			}
		})
	}
	t.Run("mesh-disabled", func(t *testing.T) {
		dir, path := prepare("mesh-disabled", []byte("invalid untouched snapshot"), false, false)
		base, stop := startCertPinMain(t, dir, false, "-revocation-mesh-outbox-store", path)
		var feed revocationFeed
		certPinStartupGet(t, base, "/admin/revocations", &feed)
		stop()
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "invalid untouched snapshot" {
			t.Fatal("unused store touched")
		}
	})
	t.Log("actual main: 4 valid variants across 2 starts each, 11 refused, mesh-disabled does not load the unused outbox")
}
