package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the real constructor's fatal gate in a child process; the parent can assert no successful startup.
func TestAuthorizationSnapshotStartupValidation(t *testing.T) {
	if path := os.Getenv("DSSE_AUTHORIZATION_STARTUP_CHILD"); path != "" {
		config := serverConfig{Evaluator: testEvaluator()}
		if os.Getenv("DSSE_AUTHORIZATION_STARTUP_KIND") == "approval" {
			config.HumanApprovalStorePath = path
		} else {
			config.DelegatedGrantStorePath = path
		}
		newServerWithConfig(config)
		os.Exit(9) // Returning means invalid authorization data was accepted.
	}
	for _, kind := range []string{"grant", "approval"} {
		for _, tc := range []struct{ name, data, reason string }{
			{"empty existing file", "", "empty"}, {"null", "null", "invalid"}, {"malformed", "{bad", "invalid"},
			{"wrong stored key", `{"wrong":{"tenant_id":"tenant_lab_001","id":"right","status":"active","approval_result":"approved"}}`, "invalid saved"},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "state.json")
				if e := os.WriteFile(path, []byte(tc.data), 0600); e != nil {
					t.Fatal(e)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAuthorizationSnapshotStartupValidation$")
				cmd.Env = append(os.Environ(), "DSSE_AUTHORIZATION_STARTUP_CHILD="+path, "DSSE_AUTHORIZATION_STARTUP_KIND="+kind)
				output, err := cmd.CombinedOutput()
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ExitCode() != 1 || ctx.Err() != nil {
					t.Fatalf("startup should refuse, err=%v output=%s", err, output)
				}
				expected := "load delegated-grant store"
				if kind == "approval" {
					expected = "load human-approval event store"
				}
				if !bytes.Contains(output, []byte(expected)) || !strings.Contains(string(output), tc.reason) {
					t.Fatalf("wrong startup refusal: %s", output)
				}
				after, e := os.ReadFile(path)
				if e != nil || string(after) != tc.data {
					t.Fatal("startup modified invalid snapshot")
				}
			})
		}
	}
}
