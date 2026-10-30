package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPlannedEnvironmentMatchesShellAndInstallerReader(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("POSIX shell unavailable")
	}
	for _, value := range []string{
		`'cp-a:12379','cp-b:12379'`,
		`owner's-path\`,
		`owner's\\path`,
		`owner's "quoted" value $literal`,
		"owner's `literal` value",
	} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "deployment.env")
			if err := os.WriteFile(path, []byte(PlanEnvironmentFor("", map[string]string{"VALUE": value})), 0600); err != nil {
				t.Fatal(err)
			}
			// Execute the generated file with the real consumer, rather than a
			// test parser that repeats the writer's escaping assumptions.
			got, err := exec.Command("sh", "-c", `. "$1"; printf '%s' "$VALUE"`, "sh", path).CombinedOutput()
			if err != nil || string(got) != value {
				t.Errorf("shell roundtrip: got %q, error %v; want %q", got, err, value)
			}
			parsed, err := readEnvFile(path)
			if err != nil || parsed["VALUE"] != value {
				t.Errorf("installer roundtrip: got %q, error %v; want %q", parsed["VALUE"], err, value)
			}
		})
	}
}
