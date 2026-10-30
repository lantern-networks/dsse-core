package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func candidateDataLayer() *PlanDataLayer {
	return &PlanDataLayer{
		EtcdImage:          "registry.example/etcd@sha256:" + strings.Repeat("a", 64),
		PostgresImage:      "registry.example/spilo@sha256:" + strings.Repeat("b", 64),
		PostgresToolsImage: "registry.example/postgres-tools@sha256:" + strings.Repeat("c", 64),
		PostgresMajor:      18,
	}
}

func TestDataLayerPlanRequiresCompleteImmutablePostgres18Cohort(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.DataLayer = candidateDataLayer()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, machine := range p.MachineNames() {
		env, err := p.MachineEnvironment(machine)
		if err != nil {
			t.Fatal(err)
		}
		for key, want := range map[string]string{
			"DSSE_ETCD_IMAGE": p.DataLayer.EtcdImage, "DSSE_POSTGRES_IMAGE": p.DataLayer.PostgresImage,
			"DSSE_PSQL_IMAGE": p.DataLayer.PostgresToolsImage, "DSSE_POSTGRES_MAJOR": "18",
		} {
			if env[key] != want {
				t.Fatalf("%s received %s=%q, want %q", machine, key, env[key], want)
			}
		}
	}
	p.DataLayer.PostgresToolsImage = "postgres:latest"
	if err := p.Validate(); err == nil {
		t.Fatal("accepted a mutable init-helper image in the data-layer cohort")
	}
	p.DataLayer.PostgresToolsImage = candidateDataLayer().PostgresToolsImage
	p.DataLayer.PostgresMajor = 16
	if err := p.Validate(); err == nil {
		t.Fatal("accepted an old PostgreSQL major with the release candidate")
	}
}

func TestPostgres18PlanRendersAllDataServicesFromOneCohort(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker Compose is needed to inspect the generated services")
	}
	p := threeNodesOneRegionPlan()
	p.DataLayer = candidateDataLayer()
	dir := installerFixtureWithArchive(t, p, false)
	cmd := exec.Command("docker", "compose", "-f", filepath.Join(dir, "docker-compose.yml"),
		"--env-file", filepath.Join(dir, "deployment.env"), "config", "--format", "json")
	cmd.Dir = dir
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("the generated candidate Compose is invalid: %v", err)
	}
	var parsed struct {
		Services map[string]struct {
			Image       string            `json:"image"`
			Environment map[string]string `json:"environment"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	for service, want := range map[string]string{
		"dsse-store-a":           p.DataLayer.EtcdImage,
		"dsse-postgres-a":        p.DataLayer.PostgresImage,
		"dsse-postgres-tls-init": p.DataLayer.PostgresImage,
		"dsse-postgres-init":     p.DataLayer.PostgresToolsImage,
	} {
		if got := parsed.Services[service].Image; got != want {
			t.Errorf("%s image = %q, want %q", service, got, want)
		}
	}
	if got := parsed.Services["dsse-postgres-a"].Environment["PGVERSION"]; got != "18" {
		t.Fatalf("PostgreSQL candidate starts with PGVERSION=%q, want 18", got)
	}
}

func TestComposeRejectsMissingDataLayerEvenWithoutInstallerPreflight(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker Compose is needed to check interpolation")
	}
	dir := t.TempDir()
	if err := writeComposeFileFor(dir, foundingShape); err != nil {
		t.Fatal(err)
	}
	if err := writeEnvironment(dir, []string{"localhost"}, nil); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("docker", "compose", "-f", filepath.Join(dir, "docker-compose.yml"),
		"--env-file", filepath.Join(dir, "deployment.env"), "config", "--quiet")
	cmd.Dir = dir
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "DSSE_ETCD_IMAGE" && key != "DSSE_POSTGRES_IMAGE" && key != "DSSE_PSQL_IMAGE" {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "DSSE_") || !strings.Contains(string(output), "IMAGE") {
		t.Fatalf("Compose accepted an incomplete data-layer cohort, or failed for an unrelated reason: %v %s", err, output)
	}
}

func TestDataLayerCohortSurvivesEdgeOnlyCarry(t *testing.T) {
	p := threeRegionsMultiEdgePlan()
	p.DataLayer = candidateDataLayer()
	dir := installerFixtureWithArchive(t, p, false)
	dest := filepath.Join(t.TempDir(), "edge.tar.gz")
	if err := carryPlanMachine(p, dir, dest, p.Regions[0].Machines[1].Name); err != nil {
		t.Fatal(err)
	}
	env := fileFromTarball(t, dest, "deployment.env")
	for key, want := range map[string]string{
		"DSSE_ETCD_IMAGE":     p.DataLayer.EtcdImage,
		"DSSE_POSTGRES_IMAGE": p.DataLayer.PostgresImage,
		"DSSE_PSQL_IMAGE":     p.DataLayer.PostgresToolsImage,
		"DSSE_POSTGRES_MAJOR": "18",
	} {
		if !strings.Contains(env, key+"='"+want+"'") {
			t.Errorf("carried Edge omitted %s", key)
		}
	}
}

func TestPreflightRejectsPostgresImageWithWrongMajor(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.DataLayer = candidateDataLayer()
	dir := installerFixtureWithArchive(t, p, false)
	deps := preflightFixtureDeps(t, dir, p)
	base := deps.command
	layer := p.DataLayer
	actualMajor := 18
	deps.command = func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) > 1 && args[1] == "compose" {
			services := map[string]map[string]string{
				"cp": {"image": "dsse:release"}, "console": {"image": "dsse-console:release"},
				"dsse-store-a":           {"image": layer.EtcdImage},
				"dsse-postgres-a":        {"image": layer.PostgresImage},
				"dsse-postgres-tls-init": {"image": layer.PostgresImage},
				"dsse-postgres-init":     {"image": layer.PostgresToolsImage},
			}
			return json.Marshal(map[string]any{"services": services})
		}
		if len(args) > 1 && args[1] == "run" && strings.Contains(strings.Join(args, " "), "--entrypoint postgres") {
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "--pull=never") || !strings.Contains(joined, "--network none") || !strings.Contains(joined, "--read-only") {
				t.Fatal("PostgreSQL preflight attempted an unsafe image probe")
			}
			return []byte(fmt.Sprintf("postgres (PostgreSQL) %d.6", actualMajor)), nil
		}
		return base(ctx, args...)
	}
	if result, err := installPreflight(context.Background(), p, dir, "", deps); err != nil || !result.Ready {
		t.Fatalf("matching PostgreSQL image failed: %v", err)
	}
	if err := replaceEnvValue(filepath.Join(dir, "deployment.env"), "DSSE_POSTGRES_MAJOR", ""); err != nil {
		t.Fatal(err)
	}
	if result, err := installPreflight(context.Background(), p, dir, "", deps); err == nil || result.Ready {
		t.Fatal("preflight accepted an incomplete carried data-layer cohort")
	}
	if err := replaceEnvValue(filepath.Join(dir, "deployment.env"), "DSSE_POSTGRES_MAJOR", "18"); err != nil {
		t.Fatal(err)
	}
	actualMajor = 16
	result, err := installPreflight(context.Background(), p, dir, "", deps)
	if err == nil || result.Ready {
		t.Fatal("preflight accepted a PostgreSQL 16 binary for a PostgreSQL 18 plan")
	}
	p.DataLayer = nil
	result, err = installPreflight(context.Background(), p, dir, "", deps)
	if err == nil || result.Ready {
		t.Fatal("preflight accepted a stale PostgreSQL 18 override after the cohort left the plan")
	}
}
