package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigReceiverCannotOpenSharedAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, dsn, url, endpoints string
		refuse                    bool
	}{
		{"single CP", "postgres://user:secret@db/control", "https://cp", "", true},
		{"failover only", "postgres://user:secret@db/control", "", "a=https://cp-a;b=https://cp-b", true},
		{"both sources", "postgres://user:secret@db/control", "https://cp", "a=https://cp", true},
		{"local receiver", "", "https://cp", "", false},
		{"local failover receiver", " ", "", "a=https://cp", false},
		{"shared CP", "postgres://user:secret@db/control", " ", "\t", false},
		{"local harness", "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfigReceiverAuthority(tc.dsn, tc.url, tc.endpoints)
			if (err != nil) != tc.refuse {
				t.Fatalf("refuse=%v, err=%v", tc.refuse, err)
			}
			if err != nil && (strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), tc.dsn)) {
				t.Fatal("startup diagnostic exposed the DSN")
			}
		})
	}
}

func TestConfigReceiverProductionStartupRejectsSharedAuthority(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"single CP", []string{"-config-source-url", "https://cp.invalid"}},
		{"failover only", []string{"-config-source-endpoints", "a=https://cp.invalid"}},
		{"CP role cannot bypass", []string{"-config-source-url", "https://cp.invalid", "-control-plane"}},
		{"local store cannot bypass", []string{"-config-source-url", "https://cp.invalid", "-policy-rule-store", "memory", "-no-control-plane"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			state := filepath.Join(dir, "state")
			args := append([]string{"-postgres-dsn", "postgres://test:must-not-log-this@127.0.0.1:1/authority?sslmode=disable", "-state-dir", state}, tc.args...)
			raw, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "args.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCertPinProductionStartupKeepsAuthoredIntent$")
			cmd.Env = append(os.Environ(), "DSSE_CERTPIN_STARTUP_ARGS="+path)
			out, err := cmd.CombinedOutput()
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), "REFUSING TO START: -postgres-dsn cannot be combined") {
				t.Fatalf("receiver did not stop at authority gate: %v %s", err, out)
			}
			if strings.Contains(string(out), "must-not-log-this") || strings.Contains(string(out), "open CP-state blob store") {
				t.Fatalf("DSN leaked or database initialization reached: %s", out)
			}
			if _, err := os.Stat(state); !os.IsNotExist(err) {
				t.Fatalf("startup touched state directory: %v", err)
			}
		})
	}
}
