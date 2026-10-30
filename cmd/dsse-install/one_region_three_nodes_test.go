package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func threeNodesOneRegionPlan() *Plan {
	return &Plan{
		Profile: "one-region-three-nodes", Deployment: "example.test",
		Regions: []PlanRegion{{ID: "kiri", Founding: true, HoldsState: true,
			Entry: &PlanEntry{Mode: "tcp-pass-through", Targets: []string{"node-a", "node-b", "node-c"}, PreservesClientIP: true},
			Machines: []PlanMachine{
				{Name: "node-a", Portal: "portal-a.example.test", FailureDomain: "rack-a", Holds: heldComponents{"control-plane", "edges"}, Addresses: []string{"10.20.0.1"}, Reachable: "node-a.example.test", ReachableAddress: "10.20.0.1"},
				{Name: "node-b", Portal: "portal-b.example.test", FailureDomain: "rack-b", Holds: heldComponents{"control-plane", "edges"}, Addresses: []string{"10.20.0.2"}, Reachable: "node-b.example.test", ReachableAddress: "10.20.0.2"},
				{Name: "node-c", Portal: "portal-c.example.test", FailureDomain: "rack-c", Holds: heldComponents{"control-plane", "edges"}, Addresses: []string{"10.20.0.3"}, Reachable: "node-c.example.test", ReachableAddress: "10.20.0.3"},
			},
		}},
	}
}

func TestOneRegionThreeNodesHasIndependentStateAndEdgePlacement(t *testing.T) {
	p := threeNodesOneRegionPlan()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	r := p.Regions[0]
	for i, m := range r.Machines {
		env, err := p.MachineEnvironment(m.Name)
		if err != nil {
			t.Fatal(err)
		}
		octet := regionSubnetOctet(r.ID)
		if env["DSSE_SUBNET"] != fmt.Sprintf("10.%d.0.0/16", octet) ||
			env["DSSE_FRONT_DOOR_A"] != fmt.Sprintf("10.%d.0.5", octet) {
			t.Errorf("%s front door is outside its generated Compose subnet", m.Name)
		}
		shape := p.shapeOf(r, m)
		if !shape.runsEdges() || !shape.holdsAControlPlane() || !shape.storeSpansRegions {
			t.Fatalf("%s does not carry one full node: %+v", m.Name, shape)
		}
		if i == 0 && shape.holds != regionShapeStateBearing || i > 0 && shape.holds != regionShapeStateBearingJoin {
			t.Fatalf("%s has wrong bootstrap/join role: %+v", m.Name, shape)
		}
		if got := env["DSSE_ETCD_A_NAME"]; got != storeMemberNameForMachine(m) {
			t.Errorf("%s uses duplicate store identity %q", m.Name, got)
		}
		if got := env["DSSE_PG_A_NAME"]; got != "dsse-pg-"+m.Name {
			t.Errorf("%s uses duplicate database identity %q", m.Name, got)
		}
		if env["DSSE_CP_A_BIND"] != m.Addresses[0]+":" ||
			env["DSSE_CP_A_ADMIN_PORT"] != "19543" || env["DSSE_CP_A_DATA_PORT"] != "19545" {
			t.Errorf("%s publishes direct CP listeners outside its private address or on mismatched ports", m.Name)
		}
		if env["DSSE_CONSOLE_BIND"] != m.Addresses[0]+":" || env["DSSE_CONSOLE_PORT"] != "19544" ||
			env["DSSE_CONSOLE_LOCAL_CP_LEADER_URL"] != "https://dsse-control-plane-a:9443/leader" ||
			env["DSSE_CONSOLE_LOCAL_CP_LEADER_NAME"] != "admin.kiri.example.test" ||
			env["DSSE_CONSOLE_BACKENDS"] != "10.20.0.1:19544,10.20.0.2:19544,10.20.0.3:19544" {
			t.Errorf("%s does not use the common Console candidates with its own CP leader probe", m.Name)
		}
		if env["DSSE_EDGE_BIND"] != m.Addresses[0]+":" || strings.Count(env["DSSE_PORTAL_PEERS"], ",") != 1 {
			t.Errorf("%s does not publish its Edge privately or name both remote portal owners", m.Name)
		}
		if got := env["DSSE_ETCD_INITIAL_CLUSTER_STATE"]; got != map[bool]string{true: "new", false: "existing"}[i == 0] {
			t.Errorf("%s bootstrap state = %q", m.Name, got)
		}
		if got := strings.Count(env["DSSE_ETCD_INITIAL_CLUSTER"], "dsse-store-"); got != i+1 {
			t.Errorf("%s knows %d members at join, want %d", m.Name, got, i+1)
		}
		for _, key := range []string{"DSSE_ETCD_HOSTS", "DSSE_PG_HOSTS", "DSSE_EDGE_BACKENDS"} {
			if got := strings.Count(env[key], ",") + 1; got != 3 {
				t.Errorf("%s %s has %d members, want 3: %s", m.Name, key, got, env[key])
			}
		}
		for _, key := range []string{"DSSE_PG_PEERS", "DSSE_CP_PEERS", "DSSE_CP_DATA_PEERS"} {
			if got := strings.Count(env[key], ",") + 1; got != 2 {
				t.Errorf("%s %s has %d peers, want 2: %s", m.Name, key, got, env[key])
			}
		}
		if !strings.Contains(env["DSSE_TRUSTED_FRONT_DOORS"], fmt.Sprintf("10.%d.0.5", regionSubnetOctet(r.ID))) {
			t.Errorf("%s does not trust its local door", m.Name)
		}
		if env["DSSE_EDGE_BALANCE"] != "leastconn" || env["DSSE_STEER_MUX_ONLY"] != "true" {
			t.Errorf("%s may send separate legacy session requests to different Edges", m.Name)
		}
		if env["DSSE_CLIENTLESS_BASE_URL"] != "https://"+m.Portal {
			t.Errorf("%s browser ceremony is not pinned to its Edge", m.Name)
		}
	}
	if len(p.verifyControlPlanes()) != 3*len(controlPlaneNodeNames) {
		t.Fatal("final verification skips a control-plane machine")
	}
	order := p.InstallOrder("/opt/dsse/kiri", "/opt/dsse/plan.json")
	if !strings.Contains(order[3].Do, "dsse-edge-a && cd /opt/dsse/kiri && docker compose -p dsse --env-file deployment.env up -d --no-deps --force-recreate dsse-edge") {
		t.Fatal("the front door keeps a stale Edge container address after bootstrap rotation")
	}
}

func TestOneRegionThreeNodesFoundingArtifactsUseAllThreeEdges(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.DataLayer = candidateDataLayer()
	work := t.TempDir()
	planPath := filepath.Join(work, "plan.json")
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(work, "deployment")
	previousUmask := syscall.Umask(0o077)
	defer syscall.Umask(previousUmask)
	installFromPlan(t, planPath, dir)
	syscall.Umask(previousUmask)
	anchor, err := os.Stat(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil || anchor.Mode().Perm() != 0o644 {
		t.Fatalf("an unprivileged TLS health checker cannot read the public anchor: mode=%v err=%v", anchor, err)
	}
	anchorPEM, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(anchorPEM) {
		t.Fatal("the health-check trust anchor is not a certificate")
	}
	chainPEM, err := os.ReadFile(filepath.Join(dir, "management.crt"))
	if err != nil {
		t.Fatal(err)
	}
	leafBlock, rest := pem.Decode(chainPEM)
	issuerBlock, _ := pem.Decode(rest)
	if leafBlock == nil || issuerBlock == nil {
		t.Fatal("the CP certificate does not carry its issuing certificate")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	intermediates := x509.NewCertPool()
	intermediates.AddCert(issuer)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		DNSName: "admin.kiri.example.test", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("the CP health check cannot authenticate its actual certificate: %v", err)
	}
	front := deploymentFileContents(t, dir, "haproxy-edge.cfg")
	assertThreeNodeCPBackends(t, front, "10.20.0.1", "10.20.0.2", "10.20.0.3")
	assertThreeNodeConsoleBackends(t, front)
	checkThreeNodeHAProxySyntax(t, dir)
	if !strings.Contains(backendBlock(front, "edge_fleet"), "balance leastconn") {
		t.Fatal("the profile pins a whole NAT site to one Edge")
	}
	if !strings.Contains(backendBlock(front, "edge_fleet"), "timeout check 2s") ||
		!strings.Contains(backendBlock(front, "edge_fleet"), "default-server inter 1s fall 2 rise 2") {
		t.Fatal("Edge health detection can outlive the generated drain period")
	}
	if !strings.Contains(deploymentFileContents(t, dir, "start-edge.sh"), "DRAIN=\"-drain-period=10s\"") ||
		!strings.Contains(deploymentFileContents(t, dir, "docker-compose.yml"), "stop_grace_period: 30s") {
		t.Fatal("generated Edge launch and container shutdown do not allow the health withdrawal window")
	}
	if !strings.Contains(backendBlock(front, "edge_fleet"), "verify required ca-file /deployment/deployment-anchor.pem verifyhost agents.kiri.example.test") {
		t.Fatal("Edge health probes do not verify the deployment certificate and name")
	}

	assertThreeNodePortalRoutes(t, front, "portal-a.example.test", "10.20.0.1")
	for _, host := range []string{"10.20.0.2:8443", "10.20.0.3:8443"} {
		if !strings.Contains(front, host) {
			t.Errorf("Node A cannot balance new mux connections to %s", host)
		}
	}
	compose := deploymentFileContents(t, dir, "docker-compose.yml")
	postgresStart := strings.Index(compose, "dsse-postgres-a: &dsse-postgres")
	if postgresStart < 0 || !strings.Contains(compose[postgresStart:min(len(compose), postgresStart+240)], "restart: unless-stopped") {
		t.Fatal("a Node reboot leaves its PostgreSQL member stopped")
	}
	if !strings.Contains(compose, "DSSE_STEER_MUX_ONLY") {
		t.Fatal("Edge does not receive the legacy-session rejection gate")
	}
	if !strings.Contains(compose, "./deployment-anchor.pem:/deployment/deployment-anchor.pem:ro") {
		t.Fatal("front door cannot verify Edge health without the deployment anchor")
	}
	if !strings.Contains(compose, "${DSSE_CP_A_BIND:?set DSSE_CP_A_BIND to the Node private address}${DSSE_CP_A_ADMIN_PORT:-19543}:9443") ||
		!strings.Contains(compose, "${DSSE_CP_A_BIND:?set DSSE_CP_A_BIND to the Node private address}${DSSE_CP_A_DATA_PORT:-19545}:8443") {
		t.Fatal("direct CP listeners ignore the plan's private bind address")
	}
	if !strings.Contains(compose, "${DSSE_CONSOLE_BIND:?set DSSE_CONSOLE_BIND to the Node private address}${DSSE_CONSOLE_PORT:-19544}:8443") ||
		!strings.Contains(compose, "DSSE_CONSOLE_LOCAL_CP_LEADER_URL:") ||
		!strings.Contains(compose, "DSSE_CONSOLE_LOCAL_CP_LEADER_NAME:") {
		t.Fatal("Console does not publish its direct private listener and local leader probe")
	}
	if !strings.Contains(compose, "${DSSE_EDGE_BIND:?set DSSE_EDGE_BIND to the Node private address}${DSSE_EDGE_AGENT_PORT:-8443}:8443") ||
		!strings.Contains(compose, "${DSSE_EDGE_BIND:?set DSSE_EDGE_BIND to the Node private address}${DSSE_EDGE_ADMIN_PORT:-9443}:9443") {
		t.Fatal("other Node doorways cannot reach this Edge's private transport and health ports")
	}
	if _, err := exec.LookPath("docker"); err == nil {
		cmd := exec.Command("docker", "compose", "-f", filepath.Join(dir, "docker-compose.yml"),
			"--env-file", filepath.Join(dir, "deployment.env"), "config", "--quiet")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("founding Node is not valid compose: %v: %s", err, out)
		}
	}
	for _, m := range p.Regions[0].Machines[1:] {
		values, err := p.MachineEnvironment(m.Name)
		if err != nil {
			t.Fatal(err)
		}
		staged, err := stageForMachine(dir, values)
		if err != nil {
			t.Fatal(err)
		}
		if err := rewriteComposeFileFor(staged, p.shapeOf(p.Regions[0], m)); err != nil {
			os.RemoveAll(staged)
			t.Fatal(err)
		}
		joined := deploymentFileContents(t, staged, "docker-compose.yml")
		stagedFront := deploymentFileContents(t, staged, "haproxy-edge.cfg")
		otherIPs := []string{}
		for _, other := range p.Regions[0].Machines {
			if other.Name != m.Name {
				otherIPs = append(otherIPs, other.ReachableAddress)
			}
		}
		assertThreeNodeCPBackends(t, stagedFront, m.ReachableAddress, otherIPs...)
		assertThreeNodeConsoleBackends(t, stagedFront)
		if backendBlock(stagedFront, "console_plane") != backendBlock(front, "console_plane") {
			t.Errorf("%s Console candidate order differs from the founding doorway", m.Name)
		}
		assertThreeNodePortalRoutes(t, stagedFront, m.Portal, m.ReachableAddress)
		checkThreeNodeHAProxySyntax(t, staged)
		if !strings.Contains(joined, "dsse-store-a:") || !strings.Contains(joined, "dsse-postgres-a:") ||
			!strings.Contains(joined, "dsse-edge-a:") || strings.Contains(joined, "dsse-postgres-init:") {
			t.Errorf("%s does not render one joining voter, DB, and Edge without reinitializing the DB", m.Name)
		}
		if !strings.Contains(joined, "${DSSE_EDGE_BIND:?set DSSE_EDGE_BIND to the Node private address}${DSSE_EDGE_AGENT_PORT:-8443}:8443") {
			t.Errorf("%s does not publish its private Edge transport to peer doorways", m.Name)
		}
		if _, err := exec.LookPath("docker"); err == nil {
			cmd := exec.Command("docker", "compose", "-f", filepath.Join(staged, "docker-compose.yml"),
				"--env-file", filepath.Join(staged, "deployment.env"), "config", "--quiet")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s is not valid compose: %v: %s", m.Name, err, out)
			}
		}
		os.RemoveAll(staged)
	}
}

func assertThreeNodePortalRoutes(t *testing.T, config, localName, localIP string) {
	t.Helper()
	pool := backendBlock(config, "edge_region_portal")
	if strings.Count(pool, "    server ") != 3 || !strings.Contains(pool, "balance roundrobin") || strings.Contains(config, "edge_peer_portal_") {
		t.Fatal("browser origins do not share all three Edges")
	}
	for _, peer := range []struct{ name, ip string }{
		{"portal-a.example.test", "10.20.0.1"},
		{"portal-b.example.test", "10.20.0.2"},
		{"portal-c.example.test", "10.20.0.3"},
	} {
		host := peer.ip
		if peer.ip == localIP {
			host = "dsse-edge-a"
		}
		if !strings.Contains(config, "use_backend edge_region_portal if { req.ssl_sni -i "+peer.name+" }") ||
			!strings.Contains(pool, host+":8443 check check-ssl check-sni agents.kiri.example.test verify required ca-file /deployment/deployment-anchor.pem verifyhost agents.kiri.example.test port 9443 send-proxy") {
			t.Errorf("Portal %s does not reach the complete authenticated pool", peer.name)
		}
	}
}

func assertThreeNodeConsoleBackends(t *testing.T, config string) {
	t.Helper()
	console := backendBlock(config, "console_plane")
	if !strings.Contains(console, "balance first") ||
		!strings.Contains(console, "option httpchk GET /ready") ||
		!strings.Contains(console, "http-check expect status 200") ||
		!strings.Contains(console, "default-server inter 2s fall 2 rise 1 on-marked-down shutdown-sessions") ||
		strings.Count(console, "check-sni console.example.test verify none") != 3 {
		t.Errorf("Console backend does not follow the one CP leader in a common order: %s", console)
	}
	for _, address := range []string{"10.20.0.1:19544", "10.20.0.2:19544", "10.20.0.3:19544"} {
		if !strings.Contains(console, address) {
			t.Errorf("Console backend lacks %s", address)
		}
	}
}

func threeNodeHAProxyChecker(t *testing.T) string {
	t.Helper()
	if checker := os.Getenv("DSSE_HAPROXY_CHECK_BIN"); checker != "" {
		return checker
	}
	checker, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("install haproxy or set DSSE_HAPROXY_CHECK_BIN to run HAProxy checks")
	}
	return checker
}

func checkThreeNodeHAProxySyntax(t *testing.T, dir string, edgeCounts ...int) {
	t.Helper()
	t.Run("HAProxy syntax", func(t *testing.T) {
		checker := threeNodeHAProxyChecker(t)
		configBytes, err := os.ReadFile(filepath.Join(dir, "haproxy-edge.cfg"))
		if err != nil {
			t.Fatal(err)
		}
		config := string(configBytes)
		if !strings.HasSuffix(config, "\n") {
			t.Fatal("generated HAProxy config has no final newline")
		}
		// The production config uses a container mount and Compose-only DNS names.
		// Translate those only in a parser copy; the generated artifact is unchanged.
		checkBody := strings.ReplaceAll(config, "/deployment/deployment-anchor.pem", filepath.Join(dir, "deployment-anchor.pem"))
		checkBody = strings.NewReplacer("dsse-edge-a", "127.0.0.1", "dsse-control-plane-a", "127.0.0.1", "dsse-console", "127.0.0.1").Replace(checkBody)
		checkConfig := filepath.Join(t.TempDir(), "haproxy-check.cfg")
		if err := os.WriteFile(checkConfig, []byte(checkBody), 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(checker, "-c", "-f", checkConfig).CombinedOutput(); err != nil {
			t.Fatalf("HAProxy rejected the generated 1x3 doorway: %v\n%s", err, output)
		}
		t.Run("effective health thresholds", func(t *testing.T) {
			checkThreeNodeHAProxyHealthThresholds(t, checker, checkBody, edgeCounts...)
		})
	})
}

func assertThreeNodeCPBackends(t *testing.T, config, localIP string, peerIPs ...string) {
	t.Helper()
	if !strings.Contains(config, "    default-server inter 5s fall 3 rise 2\n") ||
		!strings.Contains(backendBlock(config, "edge_fleet"), "default-server inter 1s fall 2 rise 2") {
		t.Error("three-Node Edge fleet must withdraw draining members before listener shutdown")
	}
	admin := backendBlock(config, "cp_admin_plane")
	data := backendBlock(config, "cp_data_plane")
	if !strings.Contains(admin, "option httpchk GET /leader") {
		t.Error("CP admin backend does not check leadership")
	}
	for _, backend := range []string{admin, data} {
		if !strings.Contains(backend, "balance roundrobin") ||
			!strings.Contains(backend, "default-server inter 2s fall 2 rise 1 on-marked-down shutdown-sessions") ||
			strings.Count(backend, "verify required ca-file /deployment/deployment-anchor.pem verifyhost admin.kiri.example.test") != 3 {
			t.Errorf("CP backend does not authenticate three direct leader probes and cut old sessions: %s", backend)
		}
	}
	for _, step := range []string{
		"http-check connect port 19543 ssl sni admin.kiri.example.test",
		"http-check send meth GET uri /leader ver HTTP/1.1 hdr Host admin.kiri.example.test",
		"http-check connect ssl sni admin.kiri.example.test",
		"http-check send meth GET uri /healthz ver HTTP/1.1 hdr Host admin.kiri.example.test",
	} {
		if !strings.Contains(data, step) {
			t.Errorf("CP data backend skips a health step %q: %s", step, data)
		}
	}
	if strings.Count(data, "http-check expect status 200") != 2 {
		t.Error("CP data backend must require both leadership and responsive data listener")
	}
	if !strings.Contains(admin, "server cp-a "+localIP+":19543 check check-ssl check-sni admin.kiri.example.test") ||
		strings.Contains(admin, "server cp-a dsse-control-plane-a:9443") {
		t.Errorf("local CP admin listener does not use the same published host path as data: %s", admin)
	}
	if !strings.Contains(data, "server cp-a "+localIP+":19545 check check-ssl check-sni admin.kiri.example.test") ||
		strings.Contains(data, "server cp-a dsse-control-plane-a:8443") {
		t.Errorf("local CP data listener cannot pass the backend-wide check of its host admin port: %s", data)
	}
	for _, ip := range peerIPs {
		if !strings.Contains(admin, ip+":19543 check check-ssl check-sni admin.kiri.example.test") ||
			!strings.Contains(data, ip+":19545 check check-ssl check-sni admin.kiri.example.test") {
			t.Errorf("CP leader routing does not use %s's direct admin/data ports", ip)
		}
		if strings.Contains(admin, ip+":443") || strings.Contains(data, ip+":443") {
			t.Errorf("CP leader routing loops through %s's region doorway", ip)
		}
	}
}

func TestOneRegionThreeNodesRefusesPeerDoorwaysAsLeaderProbes(t *testing.T) {
	dir := t.TempDir()
	env := "DSSE_TOPOLOGY_PROFILE='one-region-three-nodes'\n" +
		"DSSE_EDGE_REGION='kiri'\n" +
		"DSSE_CP_A_BIND='10.20.0.1:'\n" +
		"DSSE_NODE_PORTAL_NAME='portal-a.example.test'\n" +
		"DSSE_CP_PEERS='https://admin.kiri.example.test@10.20.0.2:443,https://admin.kiri.example.test@10.20.0.3:443'\n" +
		"DSSE_CP_DATA_PEERS='10.20.0.2:19545:19543,10.20.0.3:19545:19543'\n"
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("example.test")); err == nil ||
		!strings.Contains(err.Error(), "direct CP admin port") {
		t.Fatalf("a peer doorway was accepted as a Node-specific leader probe: %v", err)
	}
}

func TestOneRegionThreeNodesRefusesAmbiguousPortalOwners(t *testing.T) {
	for _, peers := range []string{
		"portal-b.example.test@10.20.0.2,portal-b.example.test@10.20.0.3",
		"portal-a.example.test@10.20.0.2,portal-c.example.test@10.20.0.3",
		"portal-b.example.test@10.20.0.2,portal-c.example.test@10.20.0.2",
		"portal-b.example.test@10.20.0.1,portal-c.example.test@10.20.0.3",
		"portal-b.example.test@10.20.0.2:443,portal-c.example.test@10.20.0.3",
	} {
		_, _, err := oneRegionThreeNodesPortalRoutes(map[string]string{
			"DSSE_NODE_PORTAL_NAME":    "portal-a.example.test",
			"DSSE_EDGE_CHECK_TLS_NAME": "agents.kiri.example.test",
			"DSSE_EDGE_BIND":           "10.20.0.1:",
			"DSSE_PORTAL_PEERS":        peers,
		})
		if err == nil {
			t.Errorf("ambiguous or doorway-routed portal peers accepted: %s", peers)
		}
	}
}

func TestOneRegionThreeNodesRejectsDuplicateNodeAddresses(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.Regions[0].Machines[1].ReachableAddress = p.Regions[0].Machines[0].ReachableAddress
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "distinct local and peer-reachable") {
		t.Fatalf("two portal owners share one peer address: %v", err)
	}
}

func TestOneRegionThreeNodesAdmitsJoinersAsLearners(t *testing.T) {
	p := threeNodesOneRegionPlan()
	steps := p.InstallOrder("/tmp/deployment", "/tmp/plan.json")
	if !strings.Contains(steps[1].Needs, "each Node's agent and portal names resolve to that Node's own public entry address") ||
		!strings.Contains(steps[1].Needs, "every Node doorway routes each portal SNI") {
		t.Fatal("the install order does not describe three independent entries with shared browser callbacks")
	}
	for _, step := range steps {
		if strings.Contains(step.Do, "-start-node") && !strings.Contains(step.Needs, "all three Portal names") {
			t.Fatalf("one-region three-node Edge needs all Portal names: %s", step.Needs)
		}
	}
	var order []string
	lastPromotion, syncStep := -1, -1
	for _, s := range steps {
		if strings.Contains(s.Do, " member add ") || strings.Contains(s.Do, " member promote ") {
			order = append(order, s.Do)
		}
	}
	for i, s := range steps {
		if strings.Contains(s.Do, " member promote ") {
			lastPromotion = i
		}
		if strings.Contains(s.Do, "--set synchronous_mode_strict=true") {
			syncStep = i
		}
	}
	if syncStep <= lastPromotion {
		t.Fatalf("strict synchronous mode must follow the third vote and DB replica: last promotion=%d sync=%d", lastPromotion, syncStep)
	}
	if len(order) != 4 {
		t.Fatalf("want add/promote for two joiners, got %v", order)
	}
	for i, m := range p.Regions[0].Machines[1:] {
		if !strings.Contains(order[2*i], "member add "+storeMemberNameForMachine(m)+" --learner") ||
			!strings.Contains(order[2*i+1], "member promote") ||
			!strings.Contains(order[2*i+1], storeMemberNameForMachine(m)) {
			t.Errorf("unsafe admission order for %s: %v", m.Name, order)
		}
	}
}

func TestOneRegionThreeNodesRejectsSharedFailureDomain(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.Regions[0].Machines[2].FailureDomain = "rack-a"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "failure_domain") {
		t.Fatalf("a duplicated physical failure domain passed: %v", err)
	}
}

func TestOneRegionThreeNodesRequiresDistinctPortalNames(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.Regions[0].Machines[1].Portal = p.Regions[0].Machines[0].Portal
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "portal") {
		t.Fatalf("shared browser callback owner passed: %v", err)
	}
	p = threeNodesOneRegionPlan()
	p.Regions[0].Machines[0].Portal = "agents.kiri.example.test"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "shared region plane") {
		t.Fatalf("region-balanced portal name passed: %v", err)
	}
	p = threeNodesOneRegionPlan()
	for _, m := range p.Regions[0].Machines {
		if !strings.Contains(strings.Join(p.CertificateNames(), ","), m.Portal) {
			t.Fatalf("portal %q absent from deployment transport certificate names", m.Portal)
		}
	}
}

func TestOneRegionThreeNodesRejectsIncompleteEntry(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.Regions[0].Entry.Targets[2] = "node-b"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate target passed: %v", err)
	}
}

func TestOneRegionThreeNodesRejectsUnsafeNamesBeforeRendering(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.Deployment = "example.test\nserver attacker 1.2.3.4"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "DNS-safe") {
		t.Fatalf("unsafe HAProxy name passed plan validation: %v", err)
	}
}

func TestOneRegionThreeNodesDoesNotGenerateInvalidIPv6PeerURLs(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.Regions[0].Machines[1].ReachableAddress = "2001:db8::2"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "IPv6-only") {
		t.Fatalf("unbracketed IPv6 peer address passed: %v", err)
	}
}

func TestConnectionBalancingCannotBeEnabledWithLegacySessionPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"), []byte("DSSE_EDGE_BALANCE='leastconn'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor("example.test")); err == nil || !strings.Contains(err.Error(), "DSSE_STEER_MUX_ONLY") {
		t.Fatalf("legacy sessions can be split across Edge processes: %v", err)
	}
}
