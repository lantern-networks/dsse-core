package main

import (
	"archive/tar"
	"compress/gzip"
	"github.com/lantern-networks/dsse-core/internal/posixperm"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★★★ THE CARRY IS WHERE THE ROOT KEY GOT ONTO AN EDGE MACHINE (2026-08-27, AWS lab). The directory is
// correct — authority/ holds what no running process reads — and the instruction to carry the directory put
// it on every machine anyway. This pins that the product's own carry cannot.
func TestTheCarrySetHoldsNoMintingMaterial(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "deployment.tar.gz")
	_, withheld, err := carryDeploymentFor(dir, dest, foundingShape, "", nil)
	if err != nil {
		t.Fatalf("carry: %v", err)
	}
	names, modes := entriesOfCarry(t, dest)

	for _, a := range authorityFiles {
		for _, n := range names {
			if filepath.Base(n) == a {
				t.Fatalf("%q is minting material and it is in the carry set as %q", a, n)
			}
		}
	}
	for _, n := range names {
		if strings.HasPrefix(n, authorityDirName+"/") {
			t.Fatalf("the authority directory travelled: %q", n)
		}
	}

	// ★ AND THE CONTROL: what a receiving machine cannot come up without HAS to be in there. Without this the
	// test above is satisfied by a carry set that is empty.
	for _, needed := range []string{
		"deployment-anchor.pem", "deployment.env", "docker-compose.yml",
		"transport.crt", "transport.key", "device-ca.crt", "device-ca.key",
		// region.go refuses a region that lacks this, because the Edge's policy loader would mint its own and
		// come up healthy while rejecting every bundle the control plane serves.
		agentPolicySigningKeyFile,
	} {
		if !carrySetHas(names, needed) {
			t.Fatalf("%q is not in the carry set, so the receiving machine cannot come up: %v", needed, names)
		}
	}

	// ★★★ AND THE OPERATOR IS TOLD WHAT WAS WITHHELD. A carry that silently leaves out the root key is the
	// right file and the wrong report: the whole point is that the operator can say which private keys are on
	// which machine. Measured once on the lab — the sentence did not print, because the walk skipped the
	// directory before it could name what was in it.
	if len(withheld) == 0 {
		t.Fatal("the carry answered that it withheld nothing from a deployment whose authority/ holds keys")
	}
	for _, a := range authorityFiles {
		if !carrySetHas(withheld, authorityDirName+"/"+a) {
			t.Fatalf("%q was withheld and not named: %v", a, withheld)
		}
	}

	// ★★ AND THE MODES TRAVEL. A private key that arrives 0644 is the same exposure by another route.
	//
	// ★ Checked only where the bits mean something. On Windows os.FileMode.Perm() reports a constant, so this
	// would test the operating system rather than the carry — and a machine permanently red for a reason
	// unrelated to the code stops being able to report a real break (posixperm).
	if !posixperm.Meaningful() {
		t.Log("carry file modes not checked: " + posixperm.SkipReason)
		return
	}
	for _, key := range []string{"transport.key", "device-ca.key", agentPolicySigningKeyFile} {
		if m, ok := modes[key]; ok && m&0o077 != 0 {
			t.Fatalf("%s travels as %#o — readable by more than its owner on the machine it lands on", key, m)
		}
	}
}

// ★ A CARRY NEVER OVERWRITES. The file being written holds private keys; replacing one silently is how the
// wrong deployment ends up on a machine.
func TestACarryRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "deployment.tar.gz")
	if _, _, err := carryDeploymentFor(dir, dest, foundingShape, "", nil); err != nil {
		t.Fatalf("carry: %v", err)
	}
	if _, _, err := carryDeploymentFor(dir, dest, foundingShape, "", nil); err == nil {
		t.Fatal("a second carry wrote over the first without saying so")
	}
}

// ★ AND IT REFUSES A DIRECTORY THAT IS NOT A DEPLOYMENT, rather than producing an archive of nothing that an
// operator then carries somewhere and untars.
func TestACarryRefusesWhatIsNotADeployment(t *testing.T) {
	if _, _, err := carryDeploymentFor(t.TempDir(), filepath.Join(t.TempDir(), "x.tar.gz"), foundingShape, "", nil); err == nil {
		t.Fatal("an empty directory was packed as if it were a deployment")
	}
}

func entriesOfCarry(t *testing.T, path string) ([]string, map[string]os.FileMode) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	names, modes := []string{}, map[string]os.FileMode{}
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, hdr.Name)
		modes[hdr.Name] = os.FileMode(hdr.Mode)
	}
	return names, modes
}

func carrySetHas(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}
