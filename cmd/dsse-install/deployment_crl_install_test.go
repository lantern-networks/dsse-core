package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/deploymentcrl"
)

// This follows the operator's JSON-plan input path for the three combined
// CP/L4/Edge nodes. The two independent origins must survive actual issuance
// into every issuing CA and service leaf, not just appear in a generated plan.
func TestOneRegionThreeNodePlanIssuesBothIndependentCRLOrigins(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.DeploymentCRLOrigins = []string{
		"http://crl-signer.example.test", "http://crl-replica.example.test",
	}
	work := t.TempDir()
	planPath := filepath.Join(work, "plan.json")
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPlan(planPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(work, "founding-node")
	if err := runWithDeploymentCRL(dir, strings.Join(loaded.CertificateNames(), ","), "Test Deployment", 2, false,
		loaded.DeploymentCRLOrigins, loaded.BrowserPortalNames()...); err != nil {
		t.Fatal(err)
	}
	if err := applyPlanToFoundingMachine(loaded, dir); err != nil {
		t.Fatal(err)
	}
	root, err := readCertificate(filepath.Join(dir, "root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	issuers := []*x509.Certificate{root}
	for _, name := range []string{
		"management-ca.crt", "console-server-ca.crt", "transport-ca.crt",
		"device-ca.crt", interceptionRootCertFile,
	} {
		issuer, err := readCertificate(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := issuer.CheckSignatureFrom(root); err != nil {
			t.Fatalf("%s is not issued by the planned deployment root: %v", name, err)
		}
		points, err := deploymentcrl.DistributionPoints(loaded.DeploymentCRLOrigins, root, root)
		if err != nil || !slices.Equal(issuer.CRLDistributionPoints, points) {
			t.Fatalf("%s has wrong root-issuer CDPs: %v", name, err)
		}
		issuers = append(issuers, issuer)
	}
	if err := deploymentcrl.Ready(authorityPath(dir, ""), filepath.Join(dir, "deployment-crl"), root,
		issuers, time.Now().UTC(), time.Hour); err != nil {
		t.Fatalf("issuer-signed initial CRLs are incomplete: %v", err)
	}
	for _, name := range []string{"management.crt", "console-server.crt", "transport.crt", "edge-identity.crt"} {
		chain, err := readIssuedChain(filepath.Join(dir, name), root)
		if err != nil {
			t.Fatal(err)
		}
		if len(chain) != 3 {
			t.Fatalf("%s has incomplete leaf/issuer/root chain", name)
		}
		for i := 0; i < len(chain)-1; i++ {
			points, err := deploymentcrl.DistributionPoints(loaded.DeploymentCRLOrigins, root, chain[i+1])
			if err != nil || !slices.Equal(chain[i].CRLDistributionPoints, points) {
				t.Fatalf("%s chain level %d has wrong independent CDPs: %v", name, i, err)
			}
		}
		lists := map[string][]byte{}
		for _, issuer := range chain[1:] {
			lists[deploymentcrl.Fingerprint(issuer)], err = os.ReadFile(filepath.Join(dir, "deployment-crl", deploymentcrl.Fingerprint(issuer)+".crl"))
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := deploymentcrl.VerifyStatus(chain, lists, time.Now().UTC()); err != nil {
			t.Fatalf("%s is not covered by its signed initial CRLs: %v", name, err)
		}
	}
}

func TestPlanInstallEmitsIssuerBoundCDPAndInitialSignedStatus(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deployment")
	// Follow the documented founding-host preparation exactly: MkdirAll in
	// issuance does not widen an existing private deployment directory.
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	origins := []string{"http://crl-a.example.test", "http://crl-b.example.test"}
	if err := runWithDeploymentCRL(dir, "lab.example.test", "DSSE Test", 2, false, origins); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("founder directory was expected to remain private: %v", err)
	}
	root, err := readCertificate(filepath.Join(dir, "root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	issuers := make([]*x509.Certificate, 0, 6)
	for _, name := range []string{"management-ca.crt", "console-server-ca.crt", "transport-ca.crt", "device-ca.crt", interceptionRootCertFile} {
		issuer, err := readCertificate(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		issuers = append(issuers, issuer)
		if got, err := deploymentcrl.DistributionPointsFromCertificate(issuer, root, root); err != nil || len(got) != 2 {
			t.Fatalf("%s has no root-bound CDP: %v", name, err)
		}
	}
	issuers = append(issuers, root)
	if err := deploymentcrl.Ready(authorityPath(dir, ""), filepath.Join(dir, "deployment-crl"), root, issuers, time.Now().UTC(), time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ leaf, issuer string }{
		{"management.crt", "management-ca.crt"}, {"console-server.crt", "console-server-ca.crt"},
		{"transport.crt", "transport-ca.crt"}, {"edge-identity.crt", "management-ca.crt"},
	} {
		leaf, err := readCertificate(filepath.Join(dir, tc.leaf))
		if err != nil {
			t.Fatal(err)
		}
		issuer, err := readCertificate(filepath.Join(dir, tc.issuer))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := deploymentcrl.DistributionPointsFromCertificate(leaf, root, issuer); err != nil || len(got) != 2 {
			t.Fatalf("%s has no issuer-bound CDP: %v", tc.leaf, err)
		}
	}
	if err := addHostsToDeployment(dir, "new.lab.example.test"); err != nil {
		t.Fatal(err)
	}
	updated, err := readCertificate(filepath.Join(dir, "transport.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deploymentcrl.DistributionPointsFromCertificate(updated, root, issuers[2]); err != nil {
		t.Fatal(err)
	}
	console, err := readCertificate(filepath.Join(dir, "console-server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := console.VerifyHostname("console.lab.example.test"); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"portal.lab.example.test", "agents.lab.example.test", "new.lab.example.test"} {
		if console.VerifyHostname(forbidden) == nil {
			t.Fatalf("Console-only leaf also authenticates %s", forbidden)
		}
	}
	if len(console.ExtKeyUsage) != 1 || console.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatal("Console-only leaf must not authenticate clients")
	}
	compose, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), "${DSSE_CONSOLE_TLS_CERT:-/deployment/console-server.crt}") ||
		!strings.Contains(string(compose), "./console-server.crt:/deployment/console-server.crt:ro") {
		t.Fatal("fresh compose does not present and mount the Console-only leaf")
	}
	unitBase := "dsse-crl-" + deploymentcrl.Fingerprint(root)[:12]
	publisherUnit, err := os.ReadFile(filepath.Join(dir, unitBase+"-publish.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(publisherUnit), "DynamicUser=yes") ||
		!strings.Contains(string(publisherUnit), "InaccessiblePaths=") ||
		strings.Contains(string(publisherUnit), "ReadWritePaths=") {
		t.Fatal("publisher must be keyless and unprivileged")
	}
	// The documented founding directory is owned by the human installer.
	// Renewal must run as that owner, while the publisher binds only public
	// certificates from a root-managed stage and signed DER from its source.
	privateDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	runtimeDir := "/run/" + unitBase
	publicStage := filepath.Join("/var/lib/dsse-deployment-crl", deploymentcrl.Fingerprint(root))
	activationScript, err := os.ReadFile(filepath.Join(dir, "install-deployment-crl-services.sh"))
	if err != nil {
		t.Fatal(err)
	}
	activation := string(activationScript)
	if !strings.Contains(activation, "stage_uid=0\n") {
		t.Fatal("production activation must require root ownership for staged public material and units")
	}
	for _, name := range []string{
		"root.crt", "management-ca.crt", "console-server-ca.crt", "transport-ca.crt",
		"device-ca.crt", interceptionRootCertFile,
	} {
		publicPath := shellQuote(filepath.Join(privateDir, name))
		if !strings.Contains(activation, "test -f "+publicPath+" && test ! -L "+publicPath) ||
			!strings.Contains(activation, "install -m 0644 "+publicPath+" \"$stage_tmp/"+name+"\"") ||
			!strings.Contains(activation, "cmp -s "+publicPath+" \"$stage/"+name+"\"") {
			t.Fatalf("activation does not stage and pin public issuer %s", name)
		}
	}
	if !strings.Contains(activation, "-type f -name '*.crl' | wc -l)\" -eq 6") ||
		!strings.Contains(activation, "chmod 0755 \"$source/deployment-crl\"\n") ||
		strings.Index(activation, "chmod 0755 \"$source/deployment-crl\"") >= strings.Index(activation, "systemctl enable --now "+unitBase+"-renew.timer") ||
		strings.Contains(activation, "chmod 0755 "+shellQuote(filepath.Join(privateDir, "authority"))) ||
		strings.Contains(activation, "chmod 0644 "+shellQuote(filepath.Join(privateDir, "deployment-crl-ledger.json"))) {
		t.Fatal("activation must expose only public CRL material before publisher start")
	}
	for _, name := range []string{
		"root.crt", "management-ca.crt", "console-server-ca.crt", "transport-ca.crt",
		"device-ca.crt", interceptionRootCertFile,
	} {
		bind := "BindReadOnlyPaths=" + systemdArg(filepath.Join(publicStage, name)) + ":" +
			systemdArg(filepath.Join(runtimeDir, name))
		if !strings.Contains(string(publisherUnit), bind+"\n") {
			t.Fatalf("publisher does not bind public certificate %s", name)
		}
	}
	if !strings.Contains(string(publisherUnit), "RuntimeDirectory="+unitBase+"\n") ||
		!strings.Contains(string(publisherUnit), "RuntimeDirectoryMode=0700\n") ||
		!strings.Contains(string(publisherUnit), "BindReadOnlyPaths="+systemdArg(filepath.Join(privateDir, "deployment-crl"))+":"+
			systemdArg(filepath.Join(runtimeDir, "deployment-crl"))+"\n") ||
		!strings.Contains(string(publisherUnit), "ExecStart=:"+systemdArg("/usr/local/bin/dsse-deployment-crl")+" -dir "+systemdArg(runtimeDir)+" -mode serve") ||
		strings.Contains(string(publisherUnit), "BindReadOnlyPaths="+systemdArg(filepath.Join(privateDir, "authority"))) ||
		strings.Contains(string(publisherUnit), "ExecStart=:"+systemdArg(filepath.Join(privateDir, "deployment-crl-publish.sh"))) {
		t.Fatal("publisher must execute outside the private deployment tree and bind only public inputs")
	}
	renewerUnit, err := os.ReadFile(filepath.Join(dir, unitBase+"-renew.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(renewerUnit), "RestrictAddressFamilies=AF_UNIX") ||
		!strings.Contains(string(renewerUnit), "User=DSSE_ISSUER_UID\n") ||
		!strings.Contains(string(renewerUnit), "ExecStart=:"+systemdArg("/usr/local/bin/dsse-deployment-crl")+" -dir "+systemdArg(privateDir)+" -mode renew\n") ||
		!strings.Contains(string(renewerUnit), "ReadWritePaths=") {
		t.Fatal("issuer-owner renewer lacks direct trusted binary execution, write isolation or network restriction")
	}
	timer, err := os.ReadFile(filepath.Join(dir, unitBase+"-renew.timer"))
	if err != nil || !strings.Contains(string(timer), "OnCalendar=hourly") {
		t.Fatal("signed deployment CRLs have no periodic renewal timer")
	}
	if _, err := os.Stat(filepath.Join(dir, "deployment-crl", deploymentcrl.Fingerprint(root)+".crl")); err != nil {
		t.Fatal(err)
	}
}

// Exercise the generated activation shell with an operator-owned 0700 source.
// The test process stands in for the administrator only at the UID boundary:
// systemctl is a stub, but staging, permission checks, the real CRL binary,
// and its renew/ready path are all executed against actual files.
func TestDeploymentCRLActivationAcceptsPrivateNonRootIssuerAndPinsOnlyPublicCA(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("this regression requires a non-root installer account")
	}
	work := t.TempDir()
	source := filepath.Join(work, "operator-deployment")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	origins := []string{"http://crl-a.example.test", "http://crl-b.example.test"}
	if err := runWithDeploymentCRL(source, "lab.example.test", "DSSE Test", 2, false, origins); err != nil {
		t.Fatal(err)
	}
	root, err := readCertificate(filepath.Join(source, "root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(work, "dsse-deployment-crl")
	build := exec.Command("go", "build", "-o", bin, "../dsse-deployment-crl")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build real CRL companion: %v: %s", err, output)
	}
	stageBase := filepath.Join(work, "root-stage")
	unitDir := filepath.Join(work, "systemd")
	if err := os.Mkdir(unitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeDeploymentCRLServicesAt(source, deploymentcrl.Fingerprint(root), origins,
		stageBase, bin, unitDir, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	shimDir := filepath.Join(work, "command-shims")
	if err := os.Mkdir(shimDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" {
		statShim := "#!/bin/sh\ncase \"$1:$2\" in\n'-c:%u') exec /usr/bin/stat -f '%u' \"$3\" ;;\n'-c:%a') exec /usr/bin/stat -f '%Lp' \"$3\" ;;\nesac\nexec /usr/bin/stat \"$@\"\n"
		if err := os.WriteFile(filepath.Join(shimDir, "stat"), []byte(statShim), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(shimDir, "systemctl"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	activation := filepath.Join(source, "install-deployment-crl-services.sh")
	runActivation := func() ([]byte, error) {
		cmd := exec.Command("/bin/sh", activation)
		cmd.Env = append(os.Environ(), "PATH="+shimDir+":"+os.Getenv("PATH"))
		return cmd.CombinedOutput()
	}
	if output, err := runActivation(); err != nil {
		t.Fatalf("documented non-root-mint/administrator-activation path failed: %v: %s", err, output)
	}
	stage := filepath.Join(stageBase, deploymentcrl.Fingerprint(root))
	entries, err := os.ReadDir(stage)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 6 {
		t.Fatalf("root-managed publisher stage must contain only six public CA files, found %d", len(entries))
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
			t.Fatalf("public CA stage has an unexpected entry %s: %v", entry.Name(), err)
		}
	}
	if info, err := os.Stat(filepath.Join(source, "authority", "root.key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("activation changed the source signing key protection: %v", err)
	}
	renewUnit, err := os.ReadFile(filepath.Join(unitDir, "dsse-crl-"+deploymentcrl.Fingerprint(root)[:12]+"-renew.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(renewUnit), fmt.Sprintf("User=%d\n", os.Getuid())) ||
		strings.Contains(string(renewUnit), "DSSE_ISSUER_UID") ||
		!strings.Contains(string(renewUnit), " -dir "+systemdArg(source)+" -mode renew\n") {
		t.Fatal("activated renewer does not drop to the source owner and use the original signing state")
	}
	ledger := filepath.Join(source, "authority", "deployment-crl-ledger.json")
	before, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	renew := exec.Command(bin, "-dir", source, "-mode", "renew")
	if output, err := renew.CombinedOutput(); err != nil {
		t.Fatalf("operator-owned signer could not renew its original state: %v: %s", err, output)
	}
	after, err := os.ReadFile(ledger)
	if err != nil || string(after) == string(before) {
		t.Fatalf("original ledger was not advanced by the real signer: %v", err)
	}
	if info, err := os.Stat(filepath.Join(source, "deployment-crl")); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("signed DER directory is not traversable by the keyless publisher: %v", err)
	}
	for _, entry := range mustReadDir(t, filepath.Join(source, "deployment-crl")) {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
			t.Fatalf("signed DER %s is not public read-only material: %v", entry.Name(), err)
		}
	}
	if output, err := runActivation(); err != nil {
		t.Fatalf("idempotent activation rejected the unchanged issuer: %v: %s", err, output)
	}
	// The existing root-controlled stage must reject changed CA material, not
	// silently replace its trust anchors on a rerun.
	if err := os.WriteFile(filepath.Join(source, "root.crt"), append([]byte("changed\n"), mustReadFile(t, filepath.Join(source, "root.crt"))...), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := runActivation(); err == nil {
		t.Fatalf("activation accepted a changed issuer certificate; output: %s", output)
	}
	if err := os.Remove(filepath.Join(source, "root.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(stage, "root.crt"), filepath.Join(source, "root.crt")); err != nil {
		t.Fatal(err)
	}
	if output, err := runActivation(); err == nil {
		t.Fatalf("activation accepted a symlinked issuer certificate; output: %s", output)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustReadDir(t *testing.T, path string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestDeploymentOnlinePreflightChecksActualPublishedChains(t *testing.T) {
	var publisher http.Handler
	available := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		publisher.ServeHTTP(w, r)
	}))
	defer server.Close()
	dir := filepath.Join(t.TempDir(), "deployment")
	if err := runWithDeploymentCRL(dir, "lab.example.test", "DSSE Test", 2, false, []string{server.URL}); err != nil {
		t.Fatal(err)
	}
	root, err := readCertificate(filepath.Join(dir, "root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	issuers := []*x509.Certificate{root}
	for _, name := range []string{"management-ca.crt", "console-server-ca.crt", "transport-ca.crt", "device-ca.crt", interceptionRootCertFile} {
		cert, err := readCertificate(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		issuers = append(issuers, cert)
	}
	publisher, err = deploymentcrl.Handler(filepath.Join(dir, "deployment-crl"), root, issuers, []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := checkDeploymentCRLOnline(context.Background(), dir, []string{server.URL}, true, true); err != nil {
		t.Fatalf("valid published status did not pass preflight: %v", err)
	}
	available = false
	if err := checkDeploymentCRLOnline(context.Background(), dir, []string{server.URL}, true, true); err == nil {
		t.Fatal("preflight accepted an unavailable Online status publisher")
	}
}

func TestDeploymentCRLServiceActivationPrecedesNodeStartup(t *testing.T) {
	work := t.TempDir()
	plan, err := LoadPlan(writePlan(t, work))
	if err != nil {
		t.Fatal(err)
	}
	plain := plan.InstallOrder("/opt/dsse", "/opt/plan.json")
	for _, step := range plain {
		if strings.Contains(step.Do, "install-deployment-crl-services.sh") {
			t.Fatal("a deployment with no CDPs was given a signing service")
		}
	}
	plan.DeploymentCRLOrigins = []string{"http://crl.example.test"}
	steps := plan.InstallOrder("/opt/dsse", "/opt/plan.json")
	if len(steps) != len(plain)+1 ||
		!strings.Contains(steps[1].Do, "install-deployment-crl-services.sh") ||
		!strings.Contains(steps[2].Needs, "renewal timer active") {
		t.Fatal("signed status service is not required before starting the founding node")
	}
}
