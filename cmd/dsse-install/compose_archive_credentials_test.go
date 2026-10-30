package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedComposeScopesWorkloadCredentialsToControlPlanes(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker compose is required to inspect rendered service environments")
	}
	for _, tc := range []struct {
		name  string
		shape machineShape
	}{
		{"founding", foundingShape},
		{"dedicated control plane", machineShape{holds: regionShapeStateBearing, edges: false, storeSpansRegions: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := writeComposeFileFor(dir, tc.shape); err != nil {
				t.Fatal(err)
			}
			if err := writeEnvironment(dir, []string{"localhost"}, nil); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(filepath.Join(dir, "deployment.env"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			cohort := candidateDataLayer()
			if _, err := f.WriteString("\nDSSE_IMAGE=dsse:test\nDSSE_CONSOLE_IMAGE=dsse-console:test\n" +
				"DSSE_ETCD_IMAGE=" + cohort.EtcdImage + "\nDSSE_POSTGRES_IMAGE=" + cohort.PostgresImage +
				"\nDSSE_PSQL_IMAGE=" + cohort.PostgresToolsImage + "\n"); err != nil {
				f.Close()
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("docker", "compose", "-f", filepath.Join(dir, "docker-compose.yml"),
				"--env-file", filepath.Join(dir, "deployment.env"), "config", "--format", "json")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "AWS_ACCESS_KEY_ID=operator-key", "AWS_SECRET_ACCESS_KEY=operator-secret",
				"AWS_SESSION_TOKEN=operator-session", "AWS_REGION=operator-region",
				"DSSE_ARCHIVE_AWS_ACCESS_KEY_ID=fixture-key", "DSSE_ARCHIVE_AWS_SECRET_ACCESS_KEY=fixture-secret",
				"DSSE_ARCHIVE_AWS_SESSION_TOKEN=fixture-session", "DSSE_ARCHIVE_REGION=fixture-region")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("compose config failed: %v", err)
			}
			var parsed struct {
				Services map[string]struct {
					Environment map[string]string `json:"environment"`
				} `json:"services"`
			}
			if err := json.Unmarshal(out, &parsed); err != nil {
				t.Fatal(err)
			}
			controlPlanes := 0
			for name, service := range parsed.Services {
				isCP := strings.HasPrefix(name, "dsse-control-plane")
				if isCP {
					controlPlanes++
				}
				for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION"} {
					if _, present := service.Environment[key]; present {
						t.Fatalf("compose exposed %s on %s; only the IAM launcher may export workload credentials", key, name)
					}
				}
			}
			if controlPlanes == 0 {
				t.Fatal("no control-plane service in rendered compose")
			}
			// A generic AWS CLI environment in the operator's shell must not be
			// copied into a CP for static archive mode or local-only retention.
			cmd = exec.Command("docker", "compose", "-f", filepath.Join(dir, "docker-compose.yml"),
				"--env-file", filepath.Join(dir, "deployment.env"), "config", "--format", "json")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "AWS_ACCESS_KEY_ID=operator-key", "AWS_SECRET_ACCESS_KEY=operator-secret",
				"AWS_SESSION_TOKEN=operator-session", "AWS_REGION=operator-region",
				"DSSE_ARCHIVE_AWS_ACCESS_KEY_ID=", "DSSE_ARCHIVE_AWS_SECRET_ACCESS_KEY=",
				"DSSE_ARCHIVE_AWS_SESSION_TOKEN=", "DSSE_ARCHIVE_REGION=")
			out, err = cmd.Output()
			if err != nil {
				t.Fatalf("compose config without archive credentials failed: %v", err)
			}
			if err := json.Unmarshal(out, &parsed); err != nil {
				t.Fatal(err)
			}
			for name, service := range parsed.Services {
				for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION"} {
					if _, present := service.Environment[key]; present {
						t.Fatalf("operator shell credential %s leaked into %s", key, name)
					}
				}
			}
		})
	}
}
