package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the same archive arguments that the generated CP launcher supplies,
// including explicit empty values for a local-only deployment. Run main in a
// child process because its startup checks call log.Fatal on invalid settings.
func TestColdArchiveLauncherArgsStartup(t *testing.T) {
	if raw := os.Getenv("DSSE_TEST_ARCHIVE_STARTUP_ARGS"); raw != "" {
		var args []string
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			t.Fatal(err)
		}
		flag.CommandLine = flag.NewFlagSet("edge", flag.ExitOnError)
		os.Args = append([]string{os.Args[0]}, args...)
		main()
		return
	}
	module, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	base := []string{
		"-lab-mode", "-no-control-plane", "-cold-archive-use-ssl",
		"-policy=" + filepath.Join(module, "samples/phase1/policy_lab_https_allow.json"),
		"-bundle=" + filepath.Join(module, "samples/phase1/policy_bundle_standard.json"),
		"-schema-dir=" + filepath.Join(module, "schemas"),
	}
	for _, tc := range []struct {
		name, want string
		args       []string
	}{
		{"local-only", "cold-archive disabled:", []string{"-cold-archive-endpoint=", "-cold-archive-bucket=", "-cold-archive-region=", "-cold-archive-auth-mode="}},
		{"static", "external cold-archive enabled", []string{"-cold-archive-endpoint=objects.example.test:443", "-cold-archive-bucket=fixture", "-cold-archive-region=fixture", "-cold-archive-auth-mode=static", "-cold-archive-access-key=fixture", "-cold-archive-secret-key=fixture"}},
		{"iam", "external cold-archive enabled", []string{"-cold-archive-endpoint=objects.example.test:443", "-cold-archive-bucket=fixture", "-cold-archive-region=fixture", "-cold-archive-auth-mode=iam"}},
		{"partial", "cold-archive configuration is incomplete", []string{"-cold-archive-endpoint=", "-cold-archive-bucket=fixture", "-cold-archive-auth-mode="}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			startupArgs := append(append([]string{}, base...), "-log-dir="+t.TempDir())
			args, err := json.Marshal(append(startupArgs, tc.args...))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestColdArchiveLauncherArgsStartup$")
			cmd.Env = append(os.Environ(), "DSSE_ARCHIVE_ACCESS_KEY=", "DSSE_ARCHIVE_SECRET_KEY=", "DSSE_TEST_ARCHIVE_STARTUP_ARGS="+string(args))
			out, _ := cmd.CombinedOutput()
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("startup did not reach expected archive state %q: %s", tc.want, out)
			}
		})
	}
}
