package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/archive"
)

func installerFixture(t *testing.T, p *Plan) string {
	return installerFixtureWithArchive(t, p, true)
}

func installerFixtureWithArchive(t *testing.T, p *Plan, withArchive bool) string {
	t.Helper()
	p.Publisher = "disposable-publisher"
	p.ImageRevision = "source-reviewed-fixture"
	if withArchive {
		p.Archive = &PlanArchive{Endpoint: "objects.example.test:443", Bucket: "dsse-audit-archive", Region: "fixture", AuthMode: "static", WebhookURL: "https://alerts.example.test/dsse"}
	} else {
		p.Archive = nil
	}
	root := t.TempDir()
	path := filepath.Join(root, "plan.json")
	raw, _ := json.Marshal(p)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "deployment")
	installFromPlan(t, path, dir)
	if withArchive {
		if err := replaceEnvValue(filepath.Join(dir, "deployment.env"), "DSSE_ARCHIVE_ACCESS_KEY", "fixture-access"); err != nil {
			t.Fatal(err)
		}
		if err := replaceEnvValue(filepath.Join(dir, "deployment.env"), "DSSE_ARCHIVE_SECRET_KEY", "fixture-secret"); err != nil {
			t.Fatal(err)
		}
	}
	env := readDeploymentEnv(dir)
	if env["DSSE_NODE_PORTAL_NAME"] != "" {
		names, err := portalCertificateNames(env)
		if err != nil {
			t.Fatal(err)
		}
		cert, key, ca := installerPortalPair(t, names, false)
		for name, data := range map[string][]byte{"fullchain.pem": cert, "key.pem": key, "ca.pem": ca} {
			if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := installPortalCertificate(dir, filepath.Join(root, "fullchain.pem"), filepath.Join(root, "key.pem"), filepath.Join(root, "ca.pem")); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestInstallPreflightAllowsLocalOnlyRetention(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.DataLayer = candidateDataLayer()
	dir := installerFixtureWithArchive(t, p, false)
	deps := preflightFixtureDeps(t, dir, p)
	deps.archiveCheck = func(context.Context, archive.Config) error {
		t.Fatal("local-only installation contacted external archive")
		return nil
	}
	result, err := installPreflight(context.Background(), p, dir, "", deps)
	if err != nil || !result.Ready {
		t.Fatalf("local-only installation failed preflight: %+v %v", result, err)
	}
	if err := replaceEnvValue(filepath.Join(dir, "deployment.env"), "DSSE_ARCHIVE_BUCKET", "stale-bucket"); err != nil {
		t.Fatal(err)
	}
	result, err = installPreflight(context.Background(), p, dir, "", deps)
	if err == nil || result.Ready {
		t.Fatal("local-only installation accepted stale archive configuration")
	}
}

func TestInstallPreflightJoiningNodeDoesNotRequireDatabaseInitializer(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.DataLayer = candidateDataLayer()
	founding := installerFixtureWithArchive(t, p, false)
	joining := p.Regions[0].Machines[1]
	values, err := p.MachineEnvironment(joining.Name)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := stageForMachine(founding, values)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := rewriteComposeFileFor(dir, p.shapeOf(p.Regions[0], joining)); err != nil {
		t.Fatal(err)
	}
	deps := preflightFixtureDeps(t, dir, p)
	base := deps.command
	wrongPostgresImage := false
	deps.command = func(ctx context.Context, args ...string) ([]byte, error) {
		raw, err := base(ctx, args...)
		if err != nil || len(args) < 2 || args[1] != "compose" {
			return raw, err
		}
		var config struct {
			Services map[string]map[string]string `json:"services"`
		}
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		delete(config.Services, "dsse-postgres-init") // The actual joining Compose omits it.
		if wrongPostgresImage {
			config.Services["dsse-postgres-a"]["image"] = "wrong:image"
		}
		return json.Marshal(config)
	}
	result, err := installPreflight(context.Background(), p, dir, "", deps)
	if err != nil || !result.Ready {
		t.Fatalf("joining Node rejected without a database initializer: %+v %v", result, err)
	}
	wrongPostgresImage = true
	result, err = installPreflight(context.Background(), p, dir, "", deps)
	if err == nil || result.Ready {
		t.Fatal("joining Node accepted an unreviewed PostgreSQL image")
	}
}

func TestInstallPreflightRejectsLegacyDatabaseFallbackBeforeDocker(t *testing.T) {
	p := threeNodesOneRegionPlan()
	dir := installerFixtureWithArchive(t, p, false)
	deps := setupLocalChecks{command: func(context.Context, ...string) ([]byte, error) {
		t.Fatal("missing data_layer reached Docker instead of stopping at preflight")
		return nil, nil
	}}
	result, err := installPreflight(context.Background(), p, dir, "", deps)
	if err == nil || result.Ready || len(result.Checks) == 0 ||
		result.Checks[0].Check != "reviewed data-layer cohort" || result.Checks[0].OK {
		t.Fatalf("legacy database fallback was accepted: %+v %v", result, err)
	}
}

func TestInstallPreflightUsesDedicatedIAMWorkloadCredentials(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.DataLayer = candidateDataLayer()
	dir := installerFixture(t, p)
	p.Archive.AuthMode = "iam"
	envPath := filepath.Join(dir, "deployment.env")
	for key, value := range map[string]string{
		"DSSE_ARCHIVE_AUTH_MODE": "iam", "DSSE_ARCHIVE_ACCESS_KEY": "", "DSSE_ARCHIVE_SECRET_KEY": "",
		"DSSE_ARCHIVE_AWS_ACCESS_KEY_ID": "workload-id", "DSSE_ARCHIVE_AWS_SECRET_ACCESS_KEY": "workload-secret",
		"DSSE_ARCHIVE_AWS_SESSION_TOKEN": "workload-token",
	} {
		if err := replaceEnvValue(envPath, key, value); err != nil {
			t.Fatal(err)
		}
	}
	deps := preflightFixtureDeps(t, dir, p)
	seen := false
	deps.archiveCheck = func(_ context.Context, cfg archive.Config) error {
		seen = true
		if cfg.WorkloadAccessKey != "workload-id" || cfg.WorkloadSecretKey != "workload-secret" ||
			cfg.WorkloadSessionToken != "workload-token" || !cfg.IgnoreEnvCredentials {
			t.Fatal("archive preflight did not use CP-only IAM credentials")
		}
		return nil
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "operator-id")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "operator-secret")
	result, err := installPreflight(context.Background(), p, dir, "", deps)
	if err != nil || !result.Ready || !seen {
		t.Fatalf("IAM preflight failed: %+v %v, archiveCheck=%v", result, err, seen)
	}
}

func preflightFixtureDeps(t *testing.T, dir string, p *Plan) setupLocalChecks {
	t.Helper()
	env := readDeploymentEnv(dir)
	return setupLocalChecks{platform: "linux", archiveCheck: func(context.Context, archive.Config) error { return nil }, addresses: func() ([]net.Addr, error) {
		_, m, _ := p.find(env["DSSE_NODE_NAME"])
		var out []net.Addr
		for _, ip := range m.Addresses {
			out = append(out, &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(32, 32)})
		}
		return out, nil
	}, lookup: func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
	}, command: func(_ context.Context, args ...string) ([]byte, error) {
		switch {
		case len(args) > 1 && args[1] == "info":
			return []byte(`{"Architecture":"x86_64","OSType":"linux"}`), nil
		case len(args) > 1 && args[1] == "compose":
			services := map[string]map[string]string{
				"cp": {"image": "dsse:release"}, "console": {"image": "dsse-console:release"},
			}
			if p.DataLayer != nil {
				services["dsse-store-a"] = map[string]string{"image": p.DataLayer.EtcdImage}
				services["dsse-postgres-a"] = map[string]string{"image": p.DataLayer.PostgresImage}
				services["dsse-postgres-tls-init"] = map[string]string{"image": p.DataLayer.PostgresImage}
				// The joining shape contains no database initializer. Model the
				// generated file rather than inventing a service it does not run.
				compose, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(compose), "\n  dsse-postgres-init:") {
					services["dsse-postgres-init"] = map[string]string{"image": p.DataLayer.PostgresToolsImage}
				}
			}
			return json.Marshal(map[string]any{"services": services})
		case len(args) > 2 && args[1] == "image":
			return []byte(`{"Id":"sha256:fixture","Architecture":"amd64","Os":"linux","Config":{"Labels":{"org.opencontainers.image.revision":"source-reviewed-fixture"}}}`), nil
		case len(args) > 1 && args[1] == "run":
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "--network none") || !strings.Contains(joined, "--read-only") {
				t.Fatal("unsafe image probe")
			}
			if strings.Contains(joined, "authority") || strings.Contains(joined, "docker.sock") {
				t.Fatal("image probe received issuing/host authority")
			}
			if strings.Contains(joined, "--entrypoint postgres") {
				return []byte("postgres (PostgreSQL) 18.6"), nil
			}
			if strings.Contains(joined, "-version") {
				return []byte("dsse-edge 0.4.0 (commit source-reviewed-fixture, built fixture)"), nil
			}
			if !strings.Contains(joined, "-verify-portal-certificate") {
				t.Fatalf("unexpected image command: %v", args)
			}
			return []byte(`{"ok":true}`), nil
		}
		t.Fatalf("unexpected preflight command: %v", args)
		return nil, nil
	}}
}

func TestInstallPreflightRejectsUnreachableArchive(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.DataLayer = candidateDataLayer()
	dir := installerFixture(t, p)
	deps := preflightFixtureDeps(t, dir, p)
	deps.archiveCheck = func(context.Context, archive.Config) error { return errors.New("store unavailable") }
	result, err := installPreflight(context.Background(), p, dir, "", deps)
	if err == nil {
		t.Fatal("unreachable S3 archive was not rejected")
	}
	if result.Ready {
		t.Fatal("unreachable S3 archive passed setup preflight")
	}
	for _, check := range result.Checks {
		if check.Check == "external S3 bucket" {
			if check.OK {
				t.Fatal("unreachable S3 archive was reported healthy")
			}
			return
		}
	}
	t.Fatal("archive bucket check was not run")
}

func TestInstallPreflightRefusesMissingInputDNSImageAndCertificate(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.DataLayer = candidateDataLayer()
	dir := installerFixture(t, p)
	deps := preflightFixtureDeps(t, dir, p)
	if r, err := installPreflight(context.Background(), p, dir, "", deps); err != nil || !r.Ready {
		t.Fatalf("prepared host failed: %+v %v", r, err)
	}
	for _, kind := range []string{"publisher", "revision", "DNS", "bind", "platform", "image-arch", "image-revision", "binary-revision", "image-trust"} {
		t.Run(kind, func(t *testing.T) {
			bad := deps
			original, err := os.ReadFile(filepath.Join(dir, "deployment.env"))
			if err != nil {
				t.Fatal(err)
			}
			defer os.WriteFile(filepath.Join(dir, "deployment.env"), original, 0600)
			switch kind {
			case "publisher":
				replaceEnvValue(filepath.Join(dir, "deployment.env"), "DSSE_AGENT_PUBLISHER", "")
			case "revision":
				replaceEnvValue(filepath.Join(dir, "deployment.env"), "DSSE_IMAGE_REVISION", "")
			case "DNS":
				bad.lookup = func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("unresolved") }
			case "bind":
				bad.addresses = func() ([]net.Addr, error) { return nil, nil }
			case "platform":
				bad.platform = "darwin"
			default:
				bad.command = func(ctx context.Context, args ...string) ([]byte, error) {
					if kind == "image-arch" && args[1] == "image" {
						return []byte(`{"Id":"sha256:fixture","Architecture":"arm64","Os":"linux"}`), nil
					}
					if kind == "image-revision" && args[1] == "image" {
						return []byte(`{"Id":"sha256:fixture","Architecture":"amd64","Os":"linux","Config":{"Labels":{"org.opencontainers.image.revision":"old"}}}`), nil
					}
					if kind == "binary-revision" && args[1] == "run" && args[len(args)-1] == "-version" {
						return []byte("unstamped"), nil
					}
					if kind == "image-trust" && args[1] == "run" && args[len(args)-1] != "-version" {
						return nil, errors.New("untrusted")
					}
					return deps.command(ctx, args...)
				}
			}
			if r, err := installPreflight(context.Background(), p, dir, "", bad); err == nil || r.Ready {
				t.Fatalf("accepted failed %s prerequisite: %+v", kind, r)
			}
		})
	}
}

func TestStartNodeRequiresPreflightAndClosedBootstrapOnJoiners(t *testing.T) {
	p := threeNodesOneRegionPlan()
	dir := installerFixture(t, p)
	starts := 0
	start := func(_ context.Context, gotDir, project string) error {
		starts++
		if gotDir != dir || project != "dsse" {
			t.Fatal("wrong Compose project")
		}
		return nil
	}
	failed := func(context.Context, *Plan, string, string) (installPreflightResult, error) {
		return installPreflightResult{Ready: false}, errors.New("missing prerequisites")
	}
	if r, err := startLocalNode(context.Background(), p, dir, "node-a", "", "", "", failed, start); err == nil || r.Started || starts != 0 {
		t.Fatal("started before preflight")
	}
	ready := func(context.Context, *Plan, string, string) (installPreflightResult, error) {
		return installPreflightResult{Ready: true}, nil
	}
	for i := 0; i < 2; i++ {
		if r, err := startLocalNode(context.Background(), p, dir, "node-a", "", "", "", ready, start); err != nil || !r.Started {
			t.Fatal(err)
		}
	}
	if starts != 2 {
		t.Fatal("same node cannot resume")
	}
	if r, err := startLocalNode(context.Background(), p, dir, "node-b", "", "", "", ready, start); err == nil || r.Started || starts != 2 {
		t.Fatal("started joiner with bootstrap still armed")
	}
	partial := func(context.Context, string, string) error { return errors.New("partial Compose failure") }
	if r, err := startLocalNode(context.Background(), p, dir, "node-a", "", "", "", ready, partial); err == nil || r.Started || !strings.Contains(err.Error(), "partially started") {
		t.Fatal("reported startup success after partial failure")
	}
}

func TestSharedFleetOrderClosesHumanAuthenticationSteps(t *testing.T) {
	for _, p := range []*Plan{threeNodesOneRegionPlan(), threeRegionsMultiEdgePlan(), oneRegionMultiEdgePlan()} {
		steps := p.InstallOrder("/opt/dsse", "/opt/plan.json")
		starts, activate := 0, -1
		for i, s := range steps {
			if strings.Contains(s.Do, "-start-node") {
				starts++
			}
			if strings.Contains(s.Do, "-activate-auth") {
				activate = i
			}
		}
		if starts != len(p.machines()) || activate != len(steps)-2 {
			t.Fatalf("incomplete start/activation ordering: starts=%d activate=%d", starts, activate)
		}
		if !strings.Contains(steps[2].Do, "-admin-token-file /opt/dsse/authority/operator-api-token") || !strings.Contains(steps[2].Do, "set -C") {
			t.Fatal("bootstrap output can be lost or token is not private")
		}
		if strings.Contains(steps[len(steps)-1].Do, "-admin-token <token>") {
			t.Fatal("verify asks operator to put token in argv")
		}
	}
}

func TestNetworkPlanKeepsIngressRegionalAndStateAndMeshGlobal(t *testing.T) {
	p := threeRegionsMultiEdgePlan()
	rules := planNetworkRequirements(p)
	for _, m := range p.machines() {
		if !m.Holds.has("edges") {
			continue
		}
		region, _, found := p.find(m.Name)
		if !found {
			t.Fatal("Edge missing from plan")
		}
		foundIngress, foundMesh := false, false
		for _, r := range rules {
			if r.Destination == m.Name && strings.Contains(r.Purpose, "L4 traffic") {
				foundIngress = true
				if len(r.Sources) != 1 || r.Sources[0] != region.controlPlane().Name || r.Exposure != "private" || len(r.TCPPorts) != 2 {
					t.Fatal("Edge has a cross-Region or publicly exposed ingress path")
				}
			}
			if r.Destination == m.Name && r.Purpose == "Edge mesh relay" {
				foundMesh = true
				if len(r.Sources) != 6 || r.Exposure != "private" {
					t.Fatal("cross-Region Edge mesh path lost")
				}
			}
		}
		if !foundIngress || !foundMesh {
			t.Fatalf("missing ingress or mesh rule for Edge %s", m.Name)
		}
	}
}

func TestOperatorTokenFileCannotBePublicSymlinkEmptyOrOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operator-token")
	if err := os.WriteFile(path, []byte("disposable-fixture-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := readOperatorToken(path); err != nil || token != "disposable-fixture-token" {
		t.Fatal("private token unreadable")
	}
	if err := runBootstrapAdminWithTokenFile(dir, "https://unreachable.invalid", "operator@example.invalid", "", path); err == nil || !strings.Contains(err.Error(), "never overwrite") {
		t.Fatalf("bootstrap did not reserve token before contacting API: %v", err)
	}
	for _, kind := range []string{"public", "symlink", "empty", "multiple", "large"} {
		t.Run(kind, func(t *testing.T) {
			p := filepath.Join(dir, kind)
			raw := []byte("test-token")
			mode := os.FileMode(0600)
			switch kind {
			case "public":
				mode = 0644
			case "empty":
				raw = nil
			case "multiple":
				raw = []byte("one\ntwo")
			case "large":
				raw = []byte(strings.Repeat("x", 16385))
			}
			if kind == "symlink" {
				if err := os.Symlink(path, p); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(p, raw, mode); err != nil {
					t.Fatal(err)
				}
				os.Chmod(p, mode)
			}
			if _, err := readOperatorToken(p); err == nil {
				t.Fatalf("accepted %s operator token", kind)
			}
		})
	}
}

func TestCompletePlanAndSetupInputsSurviveAllTwelveMachineCarries(t *testing.T) {
	for _, p := range []*Plan{threeNodesOneRegionPlan(), threeRegionsMultiEdgePlan()} {
		p.DataLayer = candidateDataLayer()
		issuer := installerFixture(t, p)
		// A configuration-only fixture, not evidence of real bootstrap/DB acceptance.
		if err := os.WriteFile(runtimePath(issuer, adminBootstrappedMarker), []byte("fixture-closed-bootstrap"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(privateTokenDestination(issuer), []byte("issuer-only-disposable-token"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(privateInstallReadTokenDestination(issuer), []byte("issuer-only-disposable-reader"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, m := range p.machines() {
			t.Run(p.Profile+"/"+m.Name, func(t *testing.T) {
				dir := issuer
				if m.Name != p.foundingRegion().controlPlane().Name {
					archive := filepath.Join(t.TempDir(), "node.tar.gz")
					if err := carryPlanMachine(p, issuer, archive, m.Name); err != nil {
						t.Fatal(err)
					}
					dir = unpackCarry(t, archive)
					if _, err := os.Stat(privateTokenDestination(dir)); !os.IsNotExist(err) {
						t.Fatal("operator token reached a runtime node")
					}
					if _, err := os.Stat(privateInstallReadTokenDestination(dir)); !os.IsNotExist(err) {
						t.Fatal("installation read token reached a runtime node")
					}
				}
				plan, err := loadInstallPlan(dir, "")
				if err != nil || len(plan.machines()) != len(p.machines()) {
					t.Fatal("complete plan lost in carry")
				}
				env := readDeploymentEnv(dir)
				if env["DSSE_IMAGE_REVISION"] != p.ImageRevision || env["DSSE_AGENT_PUBLISHER"] != p.Publisher || env["DSSE_NODE_NAME"] != m.Name || env[stepUpPortalCertEnvKey] != "operator" {
					t.Fatal("local setup inputs were filtered out")
				}
				if m.Holds.has("edges") && env["DSSE_NODE_PORTAL_NAME"] != "" {
					names, err := portalCertificateNames(env)
					if err != nil {
						t.Fatal(err)
					}
					cert, key, ca := installerPortalPair(t, names, false)
					input := t.TempDir()
					for name, data := range map[string][]byte{"cert": cert, "key": key, "ca": ca} {
						if err := os.WriteFile(filepath.Join(input, name), data, 0600); err != nil {
							t.Fatal(err)
						}
					}
					if err := installPortalCertificate(dir, filepath.Join(input, "cert"), filepath.Join(input, "key"), filepath.Join(input, "ca")); err != nil {
						t.Fatal(err)
					}
				}
				if result, err := installPreflight(context.Background(), plan, dir, m.Name, preflightFixtureDeps(t, dir, p)); err != nil || !result.Ready {
					t.Fatalf("receiver cannot preflight its own carry: %+v %v", result, err)
				}
			})
		}
	}
}

func TestSetupComposeDoesNotUseConflictingShellConfiguration(t *testing.T) {
	dir := installerFixture(t, threeNodesOneRegionPlan())
	t.Setenv("DSSE_IMAGE", "unreviewed:old")
	t.Setenv("DSSE_EDGE_BIND", "0.0.0.0:")
	cmd, err := installerComposeCommand(context.Background(), dir, "compose", "--env-file", "deployment.env", "config")
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, entry := range cmd.Env {
		k, v, _ := strings.Cut(entry, "=")
		env[k] = v
	}
	if env["DSSE_IMAGE"] != "dsse:release" || env["DSSE_EDGE_BIND"] != "10.20.0.1:" {
		t.Fatal("shell variables override the verified plan")
	}
}
