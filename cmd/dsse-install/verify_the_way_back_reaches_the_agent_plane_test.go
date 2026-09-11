package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ★★★ THE SHAPE THAT WAS MEASURED (2026-08-27, AWS lab, one component per machine). recovery. was created
// alongside admin. and console. on the control plane's machine, and agents. on the Edge's. Every healthy
// device was fine; the way back was dead, and nothing in the deployment said so because nothing that works
// ever sends that name.
func TestTheWayBackPointedAtTheControlPlaneIsReported(t *testing.T) {
	dir := deploymentDirForWayBackTest(t, "recovery.dsse.lab", "agents.dsse.lab")
	restore := stubPlaneNameSeams(t, map[string][]string{
		"recovery.dsse.lab": {"10.20.1.74"}, // the control plane's machine — what was actually configured
		"agents.dsse.lab":   {"10.20.1.68"}, // the Edge's
	}, errors.New("remote error: tls: no application protocol"))
	defer restore()

	where := resultNamed(t, verifyTheWayBackReachesTheAgentPlane(dir, []string{"https://agents.dsse.lab:443"}),
		"the way back reaches the agent plane")
	if where.ok {
		t.Fatalf("the recovery name points at a machine the agent plane does not, and the check passed: %s", where.note)
	}
	// The note has to carry BOTH answers, or the operator is told something is wrong and not what to change.
	for _, want := range []string{"10.20.1.74", "10.20.1.68", "recovery.dsse.lab", "agents.dsse.lab"} {
		if !strings.Contains(where.note, want) {
			t.Fatalf("the finding does not say %q, so it cannot be acted on: %s", want, where.note)
		}
	}
}

// ★ THE CONTROL, WITH THE SAME LOAD: the same deployment, the same two names, the same walk — only the
// addresses agree. Without it, the test above would pass on a check that fails for every deployment.
func TestTheWayBackOnTheAgentPlanesDoorPasses(t *testing.T) {
	dir := deploymentDirForWayBackTest(t, "recovery.dsse.lab", "agents.dsse.lab")
	restore := stubPlaneNameSeams(t, map[string][]string{
		"recovery.dsse.lab": {"10.20.1.68"},
		"agents.dsse.lab":   {"10.20.1.68"},
	}, nil)
	defer restore()

	results := verifyTheWayBackReachesTheAgentPlane(dir, []string{"https://agents.dsse.lab:443"})
	for _, r := range results {
		if !r.ok {
			t.Fatalf("a correctly configured way back was reported as a failure: %s — %s", r.name, r.note)
		}
	}
	if len(results) != 2 {
		t.Fatalf("expected both questions to be asked — where it goes and what answers — got %d", len(results))
	}
}

// ★★★ THE HANDSHAKE IS ASKED EVEN WHEN THE ADDRESSES AGREE. A record can point at the right machine and that
// machine can still not serve the name — which is the failure that survives fixing DNS, and the one an
// expired agent actually experiences.
func TestTheWayBackThatResolvesButDoesNotAnswerIsReported(t *testing.T) {
	dir := deploymentDirForWayBackTest(t, "recovery.dsse.lab", "agents.dsse.lab")
	restore := stubPlaneNameSeams(t, map[string][]string{
		"recovery.dsse.lab": {"10.20.1.68"},
		"agents.dsse.lab":   {"10.20.1.68"},
	}, errors.New("no peer certificate available"))
	defer restore()

	answers := resultNamed(t, verifyTheWayBackReachesTheAgentPlane(dir, []string{"https://agents.dsse.lab:443"}),
		"the way back answers as itself")
	if answers.ok {
		t.Fatalf("the recovery name completed no handshake and the check passed: %s", answers.note)
	}
	if !strings.Contains(answers.note, "no peer certificate available") {
		t.Fatalf("the finding does not carry what the handshake actually said: %s", answers.note)
	}
}

// ★★★ A DEPLOYMENT THAT ANNOUNCES NO WAY BACK IS A DIFFERENT FAILURE, and silence is the wrong answer to it:
// it strands every device it enrols rather than some of them.
func TestADeploymentThatAnnouncesNoWayBackIsReported(t *testing.T) {
	dir := deploymentDirForWayBackTest(t, "", "agents.dsse.lab")
	restore := stubPlaneNameSeams(t, map[string][]string{}, nil)
	defer restore()

	results := verifyTheWayBackReachesTheAgentPlane(dir, nil)
	if len(results) == 0 {
		t.Fatal("a deployment with no recovery name was passed over in silence")
	}
	if results[0].ok {
		t.Fatalf("a deployment that announces no way back was reported as fine: %s", results[0].note)
	}
}

// ★ AND A DEPLOYMENT THAT ANSWERS ON AN ADDRESS HAS NOTHING TO COMPARE. planeNamesFor derives every plane as
// that same address, so demanding two different records there would be a finding about nothing.
func TestADeploymentOnAnAddressIsNotAskedForTwoRecords(t *testing.T) {
	dir := deploymentDirForWayBackTest(t, "203.0.113.10", "203.0.113.10")
	restore := stubPlaneNameSeams(t, map[string][]string{}, errors.New("never dialled"))
	defer restore()

	for _, r := range verifyTheWayBackReachesTheAgentPlane(dir, nil) {
		if !r.ok {
			t.Fatalf("a deployment answering on an address was reported as misconfigured: %s", r.note)
		}
	}
}

// ★★★ THE NAME IS IN THE LIST THE OPERATOR IS HANDED. This is the half that was missing: the certificate
// carried recovery., deployment.env carried it, and the only place that tells an operator which records to
// create did not — so it was created by whoever noticed it, next to the names it does not belong with.
func TestTheRecoveryNameIsAPrerequisiteTheOperatorIsTold(t *testing.T) {
	const host = "deployment.example"
	want := planeNamesFor(host).Recovery
	for _, got := range planeNamesToResolve(host) {
		if strings.EqualFold(got, want) {
			return
		}
	}
	t.Fatalf("%q is in this deployment's certificate and in deployment.env, and is not among the names the "+
		"operator is told must resolve: %v", want, planeNamesToResolve(host))
}

// ★★★ AND THE LIST SAYS WHICH DOOR. "Point every one at this deployment's front door" is one instruction and
// a deployment with a machine per component has two doors — which is how recovery. ended up on the control
// plane's.
func TestEachPlaneNameIsToldWhichDoorItBelongsOn(t *testing.T) {
	const host = "deployment.example"
	p := planeNamesFor(host)
	edgeSide := map[string]bool{p.Agents: true, p.Recovery: true}
	for _, n := range planeNamesToResolve(host) {
		door := planeNameDoor(host, n)
		onEdge := strings.Contains(door, "EDGES")
		if onEdge != edgeSide[n] {
			t.Fatalf("%q is sent to %q, which is the wrong plane for it", n, door)
		}
	}
}

// deploymentDirForWayBackTest is a deployment directory the check can read: what it announces, and the anchor
// it gives its devices.
func deploymentDirForWayBackTest(t *testing.T, recovery, agents string) string {
	t.Helper()
	dir := t.TempDir()
	env := "DSSE_RECOVERY_SNI='" + recovery + "'\nDSSE_AGENT_PLANE_NAME='" + agents + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "deployment.env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "way-back-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	anchor := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "deployment-anchor.pem"), anchor, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// stubPlaneNameSeams replaces what the check does to the world — resolving a name and dialling it — so the
// REAL function is driven rather than a copy of its reasoning.
func stubPlaneNameSeams(t *testing.T, answers map[string][]string, dialErr error) func() {
	t.Helper()
	oldResolve, oldDial := resolvePlaneName, dialPlaneName
	resolvePlaneName = func(name string) ([]string, error) {
		if a, ok := answers[name]; ok {
			return a, nil
		}
		return nil, errors.New("no such host")
	}
	dialPlaneName = func(string, string, *x509.CertPool) error { return dialErr }
	return func() { resolvePlaneName, dialPlaneName = oldResolve, oldDial }
}

func resultNamed(t *testing.T, results []verifyResult, name string) verifyResult {
	t.Helper()
	for _, r := range results {
		if r.name == name {
			return r
		}
	}
	t.Fatalf("the check did not ask %q at all — it asked: %v", name, namesOf(results))
	return verifyResult{}
}

func namesOf(results []verifyResult) []string {
	out := []string{}
	for _, r := range results {
		out = append(out, r.name)
	}
	return out
}
