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
)

func TestAdmissionSnapshotProductionStartup(t *testing.T) {
	prepare := func(name string, data []byte, missing, directory bool) (string, string) {
		t.Helper()
		dir := t.TempDir()
		if root := os.Getenv("DSSE_ADMISSION_RESTORE_EVIDENCE"); root != "" {
			dir = filepath.Join(root, "after-main", name)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
		}
		seedCertPinStartup(t, dir)
		path := filepath.Join(dir, "admission.json")
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
	valid := `{"schema_version":"admission_revocations_state.v1","revoked":{"owned":"local","foreign":"foreign block"},"mesh_received":{"peer":"peer block"}}`
	for _, tc := range []struct {
		name, data string
		missing    bool
		want       map[string]string
	}{
		{"local-and-mesh", valid, false, map[string]string{"owned": "local", "foreign": "foreign block", "peer": "peer block"}},
		{"legacy", `{"schema_version":"admission_revocations_state.v1","revoked":{"owned":""}}`, false, map[string]string{"owned": ""}},
		{"empty-set", `{"schema_version":"admission_revocations_state.v1","revoked":{}}`, false, map[string]string{}},
		{"first-boot", "", true, map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := prepare(tc.name, []byte(tc.data), tc.missing, false)
			base, stop := startCertPinMain(t, dir, false, "-admission-revocation-store", path)
			var feed revocationFeed
			certPinStartupGet(t, base, "/admin/revocations", &feed)
			stop()
			if !reflect.DeepEqual(feed.Revoked, tc.want) {
				t.Fatalf("wrong restored feed: %+v", feed.Revoked)
			}
			if tc.missing {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("first boot created snapshot")
				}
			} else {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(after, []byte(tc.data)) {
					t.Fatal("startup rewrote snapshot")
				}
			}
		})
	}
	bad := map[string][]byte{
		"zero-file": {}, "truncated": []byte(`{"revoked":{"PRIVATE_SNAPSHOT_VALUE":`), "null": []byte(`null`),
		"unknown-schema":  []byte(strings.Replace(valid, "admission_revocations_state.v1", "PRIVATE_SNAPSHOT_VALUE", 1)),
		"missing-revoked": []byte(`{"schema_version":"admission_revocations_state.v1"}`),
		"duplicate-map":   []byte(`{"schema_version":"admission_revocations_state.v1","revoked":{"owned":"PRIVATE_SNAPSHOT_VALUE"},"revoked":{}}`),
		"uppercase-local": []byte(strings.Replace(valid, `"owned":`, `"OWNED":`, 1)),
		"padded-mesh":     []byte(strings.Replace(valid, `"peer":`, `" peer ":`, 1)),
		"null-reason":     []byte(strings.Replace(valid, `"local"`, `null`, 1)),
		"alias":           []byte(strings.Replace(valid, "revoked", "Revoked", 1)),
		"read-error":      nil,
	}
	module, _ := filepath.Abs("../..")
	for name, data := range bad {
		t.Run(name, func(t *testing.T) {
			dir, path := prepare(name, data, false, name == "read-error")
			args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a", "-admission-revocation-store", path}
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
			want := "load admission-revocation store: invalid admission revocation snapshot"
			if name == "read-error" {
				want = "load admission-revocation store: cannot read admission revocation snapshot"
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
