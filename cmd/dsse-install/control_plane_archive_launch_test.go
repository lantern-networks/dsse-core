package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGeneratedControlPlaneArchiveArguments(t *testing.T) {
	// Build the actual product once. Archive flags captured from the generated
	// shell script below reach this binary's real parser and constructor.
	edgeBinary := filepath.Join(t.TempDir(), "dsse-edge")
	build := exec.Command("go", "build", "-o", edgeBinary, "../dsse-edge")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual Edge: %v: %s", err, out)
	}
	for _, tc := range []struct {
		name, env, want, startup string
	}{
		{"local-only", "", "-cold-archive-auth-mode=", "cold-archive disabled:"},
		{"static", "DSSE_ARCHIVE_ENDPOINT='objects.example.test:443'\nDSSE_ARCHIVE_BUCKET='fixture'\nDSSE_ARCHIVE_AUTH_MODE='static'\nDSSE_ARCHIVE_ACCESS_KEY='fixture'\nDSSE_ARCHIVE_SECRET_KEY='fixture'\nDSSE_ARCHIVE_WEBHOOK_URL='https://alerts.example.test/dsse'\n", "-cold-archive-auth-mode=static", "external cold-archive enabled"},
		{"iam", "DSSE_ARCHIVE_ENDPOINT='objects.example.test:443'\nDSSE_ARCHIVE_BUCKET='fixture'\nDSSE_ARCHIVE_AUTH_MODE='iam'\nDSSE_ARCHIVE_WEBHOOK_URL='https://alerts.example.test/dsse'\n", "-cold-archive-auth-mode=iam", "external cold-archive enabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
				t.Fatal(err)
			}
			if tc.env != "" {
				f, err := os.OpenFile(filepath.Join(dir, "deployment.env"), os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString("\n" + tc.env)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			binary := filepath.Join(dir, "capture-arguments")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/sh", filepath.Join(dir, "start-control-plane.sh"))
			cmd.Env = append(os.Environ(), "DSSE_EDGE_BINARY="+binary, "DSSE_POSTGRES_DSN=postgres://test.invalid/test", "DSSE_MIGRATION_DIR="+dir, "DSSE_CP_STATE_DIR="+dir)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("generated launcher rejected %s: %v\n%s", tc.name, err, out)
			}
			if !strings.Contains("\n"+string(out), "\n"+tc.want+"\n") {
				t.Fatalf("generated launcher omitted %q", tc.want)
			}
			// The production launcher needs PostgreSQL before it reaches archive
			// initialization. Feed its exact generated archive argv to the real
			// binary's isolated lab startup, which exercises the same parser and
			// archive constructor without an external database.
			module, err := filepath.Abs("../..")
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"-lab-mode", "-no-control-plane", "-log-dir=" + filepath.Join(dir, "edge-logs"),
				"-policy=" + filepath.Join(module, "samples/phase1/policy_lab_https_allow.json"),
				"-bundle=" + filepath.Join(module, "samples/phase1/policy_bundle_standard.json"),
				"-schema-dir=" + filepath.Join(module, "schemas")}
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, "-cold-archive-") {
					args = append(args, line)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			actual := exec.CommandContext(ctx, edgeBinary, args...)
			actual.Env = append(os.Environ(), "DSSE_ARCHIVE_ACCESS_KEY=", "DSSE_ARCHIVE_SECRET_KEY=")
			if tc.name == "static" {
				actual.Env = append(actual.Env, "DSSE_ARCHIVE_ACCESS_KEY=fixture", "DSSE_ARCHIVE_SECRET_KEY=fixture")
			}
			startupOut, _ := actual.CombinedOutput()
			if !strings.Contains(string(startupOut), tc.startup) {
				t.Fatalf("actual Edge did not parse generated %s launcher to archive state %q: %s", tc.name, tc.startup, startupOut)
			}
		})
	}
}
