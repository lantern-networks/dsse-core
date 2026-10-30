package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/archive"
)

type installCheck struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}
type installPreflightResult struct {
	Machine string         `json:"machine"`
	Ready   bool           `json:"ready_to_start"`
	Checks  []installCheck `json:"checks"`
}
type setupLocalChecks struct {
	platform     string
	command      func(context.Context, ...string) ([]byte, error)
	lookup       func(context.Context, string) ([]net.IPAddr, error)
	addresses    func() ([]net.Addr, error)
	archiveCheck func(context.Context, archive.Config) error
}

func runInstallPreflight(ctx context.Context, p *Plan, dir, machine string) (installPreflightResult, error) {
	return installPreflight(ctx, p, dir, machine, setupLocalChecks{
		platform: runtime.GOOS,
		command: func(ctx context.Context, args ...string) ([]byte, error) {
			if len(args) > 1 && args[0] == "docker" && args[1] == "compose" {
				cmd, err := installerComposeCommand(ctx, dir, args[1:]...)
				if err != nil {
					return nil, err
				}
				return cmd.Output()
			}
			return exec.CommandContext(ctx, args[0], args[1:]...).Output()
		},
		lookup:       net.DefaultResolver.LookupIPAddr,
		addresses:    net.InterfaceAddrs,
		archiveCheck: archive.CheckBucket,
	})
}

func installPreflight(ctx context.Context, p *Plan, dir, machine string, deps setupLocalChecks) (result installPreflightResult, resultErr error) {
	result = installPreflightResult{Machine: machine, Ready: true}
	defer func() {
		if resultErr != nil {
			result.Ready = false
		}
	}()
	add := func(name string, ok bool, detail string) {
		result.Checks = append(result.Checks, installCheck{name, ok, detail})
		result.Ready = result.Ready && ok
	}
	if !declaredNodeMapProfile(p.Profile) {
		return result, fmt.Errorf("local setup preflight requires a declared shared-fleet plan")
	}
	// The generated Compose template still contains legacy image fallbacks while
	// the public 0.4.0 image digests are being finalized. Never let an omitted
	// cohort turn those fallbacks into a runnable PostgreSQL 16 installation.
	add("reviewed data-layer cohort", p.DataLayer != nil,
		"declare immutable etcd, Spilo and PostgreSQL-tools images with postgres_major 18 in data_layer before starting this node")
	if p.DataLayer == nil {
		return result, fmt.Errorf("preflight requires an explicit reviewed data_layer; no services started")
	}
	env, err := readEnvFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return result, err
	}
	if machine == "" {
		machine = env["DSSE_NODE_NAME"]
		result.Machine = machine
	}
	region, node, ok := p.find(machine)
	if !ok {
		return result, fmt.Errorf("this local machine is absent from the complete plan")
	}
	want, err := p.MachineEnvironment(machine)
	if err != nil {
		return result, err
	}
	consistent := true
	for key, value := range want {
		if actual, present := env[key]; present && actual != value {
			consistent = false
			break
		}
	}
	required := []string{"DSSE_NODE_NAME", "DSSE_TOPOLOGY_PROFILE", "DSSE_EDGE_REGION", stepUpPortalCertEnvKey}
	if p.DataLayer != nil {
		required = append(required, "DSSE_ETCD_IMAGE", "DSSE_POSTGRES_IMAGE", "DSSE_PSQL_IMAGE", "DSSE_POSTGRES_MAJOR")
	} else if strings.TrimSpace(env["DSSE_POSTGRES_MAJOR"]) != "" {
		// Removing a candidate cohort from a plan must not silently leave its
		// PostgreSQL major override in an older deployment.env.
		consistent = false
	}
	for _, key := range required {
		if env[key] != want[key] {
			consistent = false
		}
	}
	add("generated configuration matches plan", consistent, "reapply the complete plan with this machine name if configuration differs")
	if node.Holds.has("control-plane") {
		consoleLeaf := "management.crt"
		if _, err := os.Stat(filepath.Join(dir, "console-server.crt")); err == nil {
			consoleLeaf = "console-server.crt"
		}
		management, certErr := readCertificate(filepath.Join(dir, consoleLeaf))
		separate := certErr == nil
		if separate {
			for _, portal := range p.BrowserPortalNames() {
				if management.VerifyHostname(portal) == nil {
					separate = false
					break
				}
			}
		}
		add("Console certificate excludes browser Portal names", separate,
			"present a Console-only leaf without browser Portal SANs; otherwise an HTTP/2 browser may reach Console on a Portal connection")
		if len(p.DeploymentCRLOrigins) > 0 {
			issuer, issuerErr := readCertificate(filepath.Join(dir, "console-server-ca.crt"))
			consoleCertOverride, consoleKeyOverride := env[consoleCertEnvKey], env[consoleKeyEnvKey]
			if value := os.Getenv(consoleCertEnvKey); value != "" {
				consoleCertOverride = value
			}
			if value := os.Getenv(consoleKeyEnvKey); value != "" {
				consoleKeyOverride = value
			}
			consoleIssuerOnly := consoleLeaf == "console-server.crt" && management != nil && issuerErr == nil &&
				management.CheckSignatureFrom(issuer) == nil && len(management.ExtKeyUsage) == 1 &&
				management.ExtKeyUsage[0] == x509.ExtKeyUsageServerAuth &&
				(consoleCertOverride == "" || consoleCertOverride == "/deployment/console-server.crt") &&
				(consoleKeyOverride == "" || consoleKeyOverride == "/deployment/console-server.key")
			add("Console server-only issuer", consoleIssuerOnly,
				"new Online-ready deployments require a dedicated Console server CA and a server-auth-only leaf actually selected by Console; management client identities retain their issuer")
		}
	}
	if len(p.DeploymentCRLOrigins) > 0 && (node.Holds.has("control-plane") || node.Holds.has("edges")) {
		crlCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		crlErr := checkDeploymentCRLOnline(crlCtx, dir, p.DeploymentCRLOrigins,
			node.Holds.has("control-plane"), node.Holds.has("edges"))
		cancel()
		add("deployment certificate Online revocation", crlErr == nil,
			"publish each planned HTTP CDP with a current issuer-signed CRL before starting a node; unreachable, stale or revoked chains fail closed")
	}
	revision := strings.TrimSpace(env["DSSE_IMAGE_REVISION"])
	add("reviewed image revision", revision != "" && revision == p.ImageRevision && revision != "unknown" && !strings.ContainsAny(revision, " \t\r\n"), "set image_revision in the complete plan to the reviewed public commit or source content identifier used for both first-party image builds")
	add("agent package publisher", strings.TrimSpace(p.Publisher) != "" && env["DSSE_AGENT_PUBLISHER"] == p.Publisher, "set agent_publisher in the plan to the actual signed package identity before enrolling devices")
	if node.Holds.has("control-plane") {
		if p.Archive != nil {
			add("signed archive alert delivery", env["DSSE_ARCHIVE_WEBHOOK_URL"] == p.Archive.WebhookURL && len(strings.TrimSpace(env["DSSE_ARCHIVE_WEBHOOK_SIGNING_SECRET"])) >= 32,
				"set an HTTPS webhook URL in the plan and keep its signing secret in the CP's private deployment.env; configure the receiver with the same secret")
			cfg := archive.Config{
				Endpoint: env["DSSE_ARCHIVE_ENDPOINT"], Bucket: env["DSSE_ARCHIVE_BUCKET"],
				Region: env["DSSE_ARCHIVE_REGION"], AuthMode: env["DSSE_ARCHIVE_AUTH_MODE"],
				AccessKey: env["DSSE_ARCHIVE_ACCESS_KEY"], SecretKey: env["DSSE_ARCHIVE_SECRET_KEY"], UseSSL: true,
				WorkloadAccessKey: env["DSSE_ARCHIVE_AWS_ACCESS_KEY_ID"], WorkloadSecretKey: env["DSSE_ARCHIVE_AWS_SECRET_ACCESS_KEY"],
				WorkloadSessionToken: env["DSSE_ARCHIVE_AWS_SESSION_TOKEN"], IgnoreEnvCredentials: true,
			}
			_, configErr := archive.New(cfg)
			add("external S3 configuration", configErr == nil, "use TLS and a declared bucket with either a dedicated static key pair or IAM workload identity; credentials stay in private deployment.env")
			if configErr == nil {
				checkErr := fmt.Errorf("archive checker unavailable")
				if deps.archiveCheck != nil {
					checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
					checkErr = deps.archiveCheck(checkCtx, cfg)
					cancel()
				}
				add("external S3 bucket", checkErr == nil, "the existing bucket must be reachable with versioning, Object Lock and listing enabled; this read-only check does not prove Put permission")
			}
		} else {
			clean := true
			for _, key := range []string{"DSSE_ARCHIVE_ENDPOINT", "DSSE_ARCHIVE_BUCKET", "DSSE_ARCHIVE_REGION", "DSSE_ARCHIVE_AUTH_MODE", "DSSE_ARCHIVE_ACCESS_KEY", "DSSE_ARCHIVE_SECRET_KEY", "DSSE_ARCHIVE_AWS_ACCESS_KEY_ID", "DSSE_ARCHIVE_AWS_SECRET_ACCESS_KEY", "DSSE_ARCHIVE_AWS_SESSION_TOKEN"} {
				if strings.TrimSpace(env[key]) != "" {
					clean = false
				}
			}
			add("local-only audit retention", clean, "remove stale archive settings or declare an external archive in the plan; without one, hot events remain in the persistent local store")
		}
	}
	addresses, err := deps.addresses()
	assigned := map[string]bool{}
	for _, addr := range addresses {
		ip, _, e := net.ParseCIDR(addr.String())
		if e == nil {
			assigned[ip.String()] = true
		}
	}
	for _, ip := range node.Addresses {
		add("local bind address "+ip, err == nil && assigned[net.ParseIP(ip).String()], "the planned bind address must be assigned to this Linux host")
	}
	f, err := os.CreateTemp(dir, ".preflight-*")
	if err == nil {
		err = f.Sync()
		f.Close()
		os.Remove(f.Name())
	}
	add("deployment directory writable", err == nil, "the deployment directory must be on operator-provisioned persistent storage; this does not certify backups or physical durability")
	composeRaw, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		return result, err
	}
	for _, name := range filesThisMachineReads(string(composeRaw)) {
		_, err := os.Stat(filepath.Join(dir, name))
		add("mounted material "+name, err == nil, "generate/carry all required files before starting; no authority directory is mounted")
	}
	names := map[string]bool{}
	for _, peer := range p.machines() {
		names[peer.reachableName()] = true
	}
	for _, raw := range strings.Split(env["DSSE_STEPUP_PORTAL_ORIGINS"], ",") {
		if u, e := url.Parse(raw); e == nil && u.Hostname() != "" {
			names[u.Hostname()] = true
		}
	}
	for _, key := range []string{"DSSE_AGENT_PLANE_NAME", "DSSE_RECOVERY_SNI"} {
		if env[key] != "" {
			names[env[key]] = true
		}
	}
	var sortedNames []string
	for name := range names {
		sortedNames = append(sortedNames, name)
	}
	slices.Sort(sortedNames)
	for _, name := range sortedNames {
		ips, e := deps.lookup(ctx, name)
		add("DNS "+name, e == nil && len(ips) > 0, "publish the plan's private peer and public entrance names; DNS success alone is not a route or firewall test")
	}
	if node.Holds.has("edges") {
		v := verifyOneRegionThreeNodesPortalCertificate(dir, env)
		add(v.name, v.ok, v.note)
	}
	info, err := deps.command(ctx, "docker", "info", "--format", "{{json .}}")
	var daemon struct{ Architecture, OSType string }
	if err == nil {
		err = json.Unmarshal(info, &daemon)
	}
	arch := normalizeSetupArch(daemon.Architecture)
	add("Linux Docker host", err == nil && arch != "" && daemon.OSType == "linux" && deps.platform == "linux", "run preflight on the actual Linux deployment host with Docker Engine available")
	raw, err := deps.command(ctx, "docker", "compose", "-p", "dsse-preflight", "--env-file", filepath.Join(dir, "deployment.env"), "-f", filepath.Join(dir, "docker-compose.yml"), "config", "--format", "json")
	var compose struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if err == nil {
		err = json.Unmarshal(raw, &compose)
	}
	add("Compose configuration", err == nil && len(compose.Services) > 0, "Docker Compose v2 must parse all services without missing inputs; diagnostic output may contain secrets and is not echoed here")
	images := map[string]bool{}
	for _, svc := range compose.Services {
		if svc.Image != "" {
			images[svc.Image] = true
		}
	}
	var sortedImages []string
	for image := range images {
		sortedImages = append(sortedImages, image)
	}
	slices.Sort(sortedImages)
	serviceImageAvailable := false
	consoleImageAvailable := false
	serviceImage := env["DSSE_IMAGE"]
	for i, image := range sortedImages {
		raw, e := deps.command(ctx, "docker", "image", "inspect", image, "--format", "{{json .}}")
		var meta struct {
			ID           string
			Architecture string
			OS           string `json:"Os"`
			Config       struct{ Labels map[string]string }
		}
		if e == nil {
			e = json.Unmarshal(raw, &meta)
		}
		matches := e == nil && meta.OS == "linux" && normalizeSetupArch(meta.Architecture) == arch && arch != "" && meta.ID != ""
		add(fmt.Sprintf("local image %d", i+1), matches, "preload the declared Linux image for this host's architecture; preflight never pulls images or prints registry credentials")
		if image == serviceImage || image == env["DSSE_CONSOLE_IMAGE"] {
			matches = matches && revision != "" && revision != "unknown" && meta.Config.Labels["org.opencontainers.image.revision"] == revision
			add(fmt.Sprintf("first-party image revision %d", i+1), matches, "service and Console images must carry the plan's reviewed OCI revision label; mutable tags alone are not build identity")
		}
		if image == serviceImage {
			serviceImageAvailable = matches
		}
		if image == env["DSSE_CONSOLE_IMAGE"] {
			consoleImageAvailable = matches
		}
	}
	add("declared service image", serviceImageAvailable, "the parsed Compose services must use the generated plan's reviewed service image")
	if node.Holds.has("control-plane") {
		add("declared Console image", consoleImageAvailable, "the parsed Compose services must use the generated plan's reviewed Console image")
		shape := p.shapeOf(region, node)
		if d := p.DataLayer; d != nil && shape.holds.holdsState() {
			for _, service := range [][2]string{
				{"dsse-store-a", d.EtcdImage}, {"dsse-postgres-a", d.PostgresImage},
				{"dsse-postgres-tls-init", d.PostgresImage},
			} {
				actual, present := compose.Services[service[0]]
				add("planned data image "+service[0], present && actual.Image == service[1],
					"the generated Compose service must use the immutable data-layer image declared by the plan")
			}
			// The database and role are initialized only by the founding
			// machine. Joining state-bearing nodes deliberately omit this
			// service; requiring it here prevents the second Node from booting.
			init, present := compose.Services["dsse-postgres-init"]
			initExpected := shape.holds == regionShapeStateBearing
			add("planned data image dsse-postgres-init", present == initExpected && (!present || init.Image == d.PostgresToolsImage),
				"only the founding machine must run the immutable PostgreSQL init image; joining machines must not reinitialize the database")
			// A digest proves which image was pulled, but not which PostgreSQL
			// executable it contains. Check the actual binary before first boot.
			raw, e := deps.command(ctx, "docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only", "--entrypoint", "postgres", d.PostgresImage, "--version")
			prefix := fmt.Sprintf("postgres (PostgreSQL) %d.", d.PostgresMajor)
			add("PostgreSQL image major", e == nil && strings.HasPrefix(strings.TrimSpace(string(raw)), prefix),
				"the selected immutable Spilo image must contain the PostgreSQL major declared by the plan")
		}
	}
	if serviceImageAvailable {
		raw, e := deps.command(ctx, "docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint", "dsse-edge", serviceImage, "-version")
		add("service binary revision", e == nil && strings.Contains(string(raw), "(commit "+revision+","), "the actual service binary must report the reviewed revision, not an unstamped or differently built binary")
	}
	if node.Holds.has("edges") && serviceImageAvailable {
		err := verifyPortalInsideImage(ctx, dir, serviceImage, env, deps.command)
		add("Portal certificate inside service image", err == nil, "the actual service image must trust the certificate for every Portal name this Edge serves; provision approved private CA with -portal-ca instead of disabling validation")
	}
	if !result.Ready {
		return result, fmt.Errorf("preflight failed; correct the listed inputs and rerun before starting services")
	}
	return result, nil
}

func normalizeSetupArch(arch string) string {
	switch arch {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	}
	return ""
}

func verifyPortalInsideImage(ctx context.Context, dir, image string, env map[string]string, command func(context.Context, ...string) ([]byte, error)) error {
	staged, err := os.MkdirTemp("", "dsse-portal-preflight-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staged)
	public := map[string]string{
		"DSSE_TOPOLOGY_PROFILE":      env["DSSE_TOPOLOGY_PROFILE"],
		"DSSE_NODE_PORTAL_NAME":      env["DSSE_NODE_PORTAL_NAME"],
		"DSSE_STEPUP_PORTAL_ORIGINS": env["DSSE_STEPUP_PORTAL_ORIGINS"],
	}
	if err := os.WriteFile(filepath.Join(staged, "deployment.env"), []byte(PlanEnvironmentFor("", public)), 0600); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(staged, "clientless"), 0700); err != nil {
		return err
	}
	clientless, err := filepath.Abs(filepath.Join(dir, "clientless"))
	if err != nil {
		return err
	}
	raw, err := command(ctx, "docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid", "--mount", "type=bind,src="+staged+",dst=/check,readonly", "--mount", "type=bind,src="+clientless+",dst=/check/clientless,readonly", "--entrypoint", "dsse-install", image, "-verify-portal-certificate", "-dir", "/check")
	var result struct {
		OK bool `json:"ok"`
	}
	if err != nil || json.Unmarshal(raw, &result) != nil || !result.OK {
		return fmt.Errorf("service image refused the Portal chain")
	}
	return nil
}
