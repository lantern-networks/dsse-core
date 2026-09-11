package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ★★★ THE MATERIAL HAS TO BE TRIED, NOT TRUSTED (this repository has paid for the opposite). An installer
// that writes files which look right and do not chain is worse than one that fails: the failure surfaces on
// the day a device tries to verify, over the channel that verification was going to repair.
func TestTheInstallerProducesMaterialThatChains(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example,127.0.0.1", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}

	root := readCert(t, filepath.Join(dir, "root.crt"))
	pool := x509.NewCertPool()
	pool.AddCert(root)

	// Every certificate this deployment presents must chain to the one anchor it distributes. That is the
	// whole reason an installer mints these rather than each process self-signing.
	for _, leaf := range []string{"management", "transport"} {
		chain := readChain(t, filepath.Join(dir, leaf+".crt"))
		if len(chain) < 2 {
			t.Fatalf("%s.crt carries %d certificate(s); a leaf served without its issuer is a chain nobody "+
				"can complete", leaf, len(chain))
		}
		inter := x509.NewCertPool()
		for _, c := range chain[1:] {
			inter.AddCert(c)
		}
		if _, err := chain[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("%s does not chain to the deployment anchor: %v", leaf, err)
		}
		if err := chain[0].VerifyHostname("dsse.example"); err != nil {
			t.Errorf("%s does not name where this deployment answers: %v", leaf, err)
		}
	}

	// The device CA is an issuer, not a leaf, and it chains too — the control plane signs device certificates
	// under it, and a device resolves its organization from the chain.
	if _, err := readCert(t, filepath.Join(dir, "device-ca.crt")).Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("the device CA does not chain to the deployment anchor: %v", err)
	}

	// ★ The keys are files by design, so they have to be files only their owner can read.
	//
	// ★★ AND THE MINTING MATERIAL IS NO LONGER BESIDE THEM (2026-08-27). The four this installer signs with and
	// no running process reads live under authority/, which no service mounts. The mode requirement is the same
	// wherever they are; where they are is what stopped the deployment handing its root key to five containers.
	for _, secret := range []string{"root.key", "management-ca.key", "transport-ca.key", "device-ca.key",
		"management.key", "transport.key", "bundle-signing.key"} {
		at := filepath.Join(dir, secret)
		if isAuthorityFile(secret) {
			at = authorityPath(dir, secret)
		}
		info, err := os.Stat(at)
		if err != nil {
			t.Errorf("%s is missing: %v", secret, err)
			continue
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s is mode %o; the default key store is a directory rather than an HSM, so it has to "+
				"actually be readable by nobody else", secret, perm)
		}
	}

	// ★ A deployment directory has to be self-contained: the Edge's -schema-dir and -policy defaults are
	// repo-relative, and a deployment that followed a document not mentioning them died on a path its
	// operator never chose.
	for _, needed := range []string{"schemas/policy.schema.json", "policy.json", "policy-bundle.json",
		"deployment-anchor.pem"} {
		if _, err := os.Stat(filepath.Join(dir, needed)); err != nil {
			t.Errorf("the deployment directory is not self-contained: %s is missing", needed)
		}
	}

	// ★ The bundle is SIGNED, not mock-signed. Shipping the loader's development affordance from an installer
	// is how it becomes the production default by inertia.
	b, err := os.ReadFile(filepath.Join(dir, "policy-bundle.json"))
	if err != nil {
		t.Fatalf("read the bundle: %v", err)
	}
	for _, forbidden := range []string{"unsigned-local-bundle", "mock-signature", "mock-local-signing-key"} {
		if strings.Contains(string(b), forbidden) {
			t.Errorf("the shipped bundle still carries %q", forbidden)
		}
	}
	if !strings.Contains(string(b), "ed25519:") || !strings.Contains(string(b), "ed25519-public:") {
		t.Error("the shipped bundle is not signed with a key the loader will check it against")
	}
}

// ★★★ A SECOND RUN MUST NOT REPLACE AN AUTHORITY. Devices adopt anchors; one replaced without the
// announce/measure/retire sequence strands every device that had adopted it, and they cannot be repaired over
// the channel that just broke.
func TestRunningTheInstallerTwiceChangesNothing(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("first install: %v", err)
	}
	before := readCert(t, filepath.Join(dir, "root.crt")).Raw
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("second install: %v", err)
	}
	if after := readCert(t, filepath.Join(dir, "root.crt")).Raw; string(after) != string(before) {
		t.Fatal("a second run replaced the deployment's root — every anchor already distributed is now orphaned")
	}
}

// ★ And it refuses the two things it cannot guess, rather than choosing for the operator.
func TestTheInstallerRefusesWhatItCannotInvent(t *testing.T) {
	if err := run("", "dsse.example", "Test", 10, false); err == nil {
		t.Error("an installer with nowhere to put the keys must refuse; a temporary path loses them")
	}
	if err := run(t.TempDir(), "", "Test", 10, false); err == nil {
		t.Error("a certificate that names nowhere is one a device cannot tell from an outage")
	}
}

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	chain := readChain(t, path)
	if len(chain) == 0 {
		t.Fatalf("%s holds no certificate", path)
	}
	return chain[0]
}

func readChain(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []*x509.Certificate
	for rest := raw; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse a certificate in %s: %v", path, err)
		}
		out = append(out, c)
	}
	return out
}

// ★★★ THE SECRETS HAVE TO BE REAL, DIFFERENT, AND PRIVATE (2026-08-22, measured against what an Edge
// refuses). It rejects a short secret, it rejects the development default it ships for local use, and it
// rejects a workload-attestation secret equal to the connector one. An installer that emitted placeholders
// would hand an operator three things to invent at the worst moment, and the shortest path from there is the
// default being refused.
func TestTheGeneratedSecretsAreRealAndDistinct(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	env := filepath.Join(dir, "deployment.env")
	info, err := os.Stat(env)
	if err != nil {
		t.Fatalf("the deployment has no environment file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("deployment.env is mode %o; it IS credentials and belongs with the keys", perm)
	}
	// ★ READ IT THE WAY THE TOOL DOES (2026-08-23). This loop parsed the file itself and broke the moment the
	// writer started quoting values — a third reader of one format, in the same package as the writer. The
	// tool's own reader is the only one that cannot drift from it.
	values, err := readEnvFile(env)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]string{}
	for _, k := range []string{"ADMIN_TOKEN", "CONNECTOR_SECRET", "WORKLOAD_SECRET", "AUDIT_INGEST_TOKEN",
		"EDGE_CP_TOKEN", "PG_PASSWORD"} {
		v, ok := values[k]
		if !ok {
			t.Errorf("%s is missing — the deployment refuses to start without it", k)
			continue
		}
		if len(v) < 32 {
			t.Errorf("%s is %d characters; an Edge refuses anything short", k, len(v))
		}
		if strings.Contains(strings.ToUpper(v), "TODO") || strings.Contains(v, "GENERATE-A-LONG") {
			t.Errorf("%s is a placeholder, which is a value somebody will replace with the shortest thing "+
				"that passes", k)
		}
		if other, clash := seen[v]; clash {
			t.Errorf("%s and %s are the SAME value; the Edge refuses two of these being equal", k, other)
		}
		seen[v] = k
	}
	if len(seen) != 6 {
		t.Errorf("expected six distinct secrets, got %d", len(seen))
	}
	if values["EDGE_HOST"] != "dsse.example" {
		t.Errorf("the environment does not say where this deployment answers: %q", values["EDGE_HOST"])
	}

	// ★★★ AND EVERY VALUE IS QUOTED, because the start scripts SOURCE this file. A region entry list contains
	// ';' by its own format, and unquoted it made every node of a deployment exit 127 at once — the shell
	// assigned the first entry and tried to run the second.
	raw, err := os.ReadFile(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Errorf("unreadable line in deployment.env: %q", line)
			continue
		}
		if !strings.HasPrefix(v, "'") || !strings.HasSuffix(v, "'") {
			t.Errorf("deployment.env is sourced by a shell and this value is unquoted, so a metacharacter in "+
				"it would be executed: %q", line)
		}
	}
}

// TestASecondRegionIsNotASecondDeployment — invariant 11, at the one moment it is still cheap to catch. An
// operator standing up region B naturally re-runs the command that stood up region A, which mints a SECOND
// anchor; both regions then come up healthy and the failure appears later, on a device that moves between
// them and is served a certificate from an issuer it has never heard of.
func TestASecondRegionIsNotASecondDeployment(t *testing.T) {
	empty := t.TempDir()
	err := regionInstall(empty, "region-b", machineShape{holds: regionShapeEdgesOnly, edges: true})
	if err == nil {
		t.Fatal("installing a region into a directory with no authorities was accepted — that mints a second " +
			"deployment and says nothing")
	}
	if !strings.Contains(err.Error(), "SECOND") {
		t.Errorf("the refusal does not say what would have gone wrong: %v", err)
	}

	// Carried material: the same deployment, prepared for another region, minting nothing.
	carried := t.TempDir()
	if err := run(carried, "dsse.example", "Test Org", 1, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(carried, "deployment-anchor.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := regionInstall(carried, "region-b", machineShape{holds: regionShapeEdgesOnly, edges: true}); err != nil {
		t.Fatalf("preparing a carried deployment as another region: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(carried, "deployment-anchor.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("preparing a region replaced the deployment's anchor — a device that moves between regions " +
			"would meet an issuer it has never heard of")
	}
	env, err := readEnvFile(filepath.Join(carried, "deployment.env"))
	if err != nil {
		t.Fatal(err)
	}
	if env["DSSE_EDGE_REGION"] != "region-b" {
		t.Errorf("the region was not recorded: %q", env["DSSE_EDGE_REGION"])
	}
	if _, named := env["DSSE_REGION_ENDPOINTS"]; !named {
		t.Error("the region entry list has no line at all, so nothing tells the operator it has to be filled " +
			"in once every region exists")
	}
	if env["DSSE_REGION_ENDPOINTS"] != "" {
		t.Errorf("the region entry list was pre-filled with %q; it cannot be complete until every region "+
			"exists, and a half-written list leaves an Edge handing devices a map missing regions",
			env["DSSE_REGION_ENDPOINTS"])
	}
}

// TestComposeRunsTheGeneratedScripts is the one property that keeps the compose file from becoming a second
// description of the procedure: every service must START one of the generated scripts, and carry no flag of
// its own.
//
// ★ AND IT MUST BE AN ENTRYPOINT, NOT A COMMAND (2026-08-23, found by running it). A DSSE image's entrypoint
// IS the binary, so a compose `command` is appended to it as an argument — the script never runs, the binary
// starts on its own defaults, and the control plane says "REFUSING TO START: this Edge has no control plane".
// A message that cannot be true, from a script that was never executed.
func TestComposeRunsTheGeneratedScripts(t *testing.T) {
	dir := t.TempDir()
	if err := writeComposeFile(dir); err != nil {
		t.Fatalf("writeComposeFile: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(body)
	for _, want := range []string{
		`entrypoint: ["/deployment/start-control-plane.sh"]`,
		`entrypoint: ["/deployment/start-edge.sh"]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the compose file does not start the generated script: %s missing", want)
		}
	}
	flag := regexp.MustCompile(`"-[a-z][a-z0-9-]{3,}[=" ]`)
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue // an explanation naming a flag, or naming command:, is not a second copy of it
		}
		// ★ THE RULE IS ABOUT THE SCRIPTS, NOT ABOUT command: (2026-08-24, narrowed when the database tier
		// arrived). A DSSE image's entrypoint IS the binary, so a start script given as command: becomes an
		// ARGUMENT and never runs. A one-shot psql container is not a DSSE image and command: is exactly how
		// it takes its work. What must never happen is a start script arriving as command:.
		if strings.HasPrefix(trimmed, "command:") && strings.Contains(line, "/deployment/") {
			t.Errorf("a start script is given as command:, which a DSSE image appends to its own entrypoint "+
				"as an argument — it would never run: %s", trimmed)
		}
		// No flag of its own: the procedure lives in the scripts.
		if flag.MatchString(line) {
			t.Errorf("the compose file carries a DSSE flag, so the procedure is described twice: %s", line)
		}
	}
}

// TestComposeIsNotRewrittenOverAnOperatorsEdits — the same rule the rest of the deployment directory follows.
func TestComposeIsNotRewrittenOverAnOperatorsEdits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte("# edited by the operator\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeComposeFile(dir); err != nil {
		t.Fatalf("writeComposeFile: %v", err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != "# edited by the operator\n" {
		t.Error("the installer overwrote a compose file an operator had edited")
	}
}

// ★★★ -host IS FOR MINTING, AND A REPAIR WAS DEMANDING IT (2026-08-27, found walking the paid lane).
//
// Refreshing an existing deployment's derived files failed with "a deployment's certificates have to name where
// it answers" — about certificates minted long before and not touched by the act. Worse than the inconvenience:
// the value is IGNORED on that path (the repair reads EDGE_HOST from deployment.env), so the flag was required,
// unused, and teaching an operator that restating it mattered. Restating it WRONG is how a deployment ends up
// unreachable under the name its certificate carries.
func TestARepairDoesNotDemandTheHostItAlreadyKnows(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "the-deployment.example", "Example", 3, false); err != nil {
		t.Fatalf("mint: %v", err)
	}
	// The second run is a repair: same directory, no -host. It must not refuse, and it must not mint again.
	before, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		t.Fatalf("read anchor: %v", err)
	}
	if err := run(dir, "", "", 3, false); err != nil {
		t.Fatalf("a repair of an existing deployment asked for -host: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		t.Fatalf("read anchor: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the repair replaced the deployment's anchor — that is a rotation, and it orphans every device")
	}
	// And a FIRST run still has to be told where the deployment answers.
	if err := run(t.TempDir(), "", "", 3, false); err == nil {
		t.Fatal("minting a new deployment with no -host was allowed; its certificates would name nothing")
	}
}
