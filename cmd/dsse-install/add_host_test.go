package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ★ THE TWO WAYS THIS CAN BE WRONG, both asserted on one deployment: it can fail to add the new name, and it
// can lose the old ones. The second is the failure this exists to fix, arrived at from the other side — a
// remote endpoint whose deployment did not know it existed — so a version that "adds" by replacing would
// reproduce it exactly.
func TestAddHostKeepsTheOldNamesAndTheAnchor(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "edge.example.test,10.0.0.5", "Test Deployment", 5, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	anchorBefore, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		t.Fatal(err)
	}
	before, ipsBefore, err := hostsInCertificate(filepath.Join(dir, "transport.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(before) == 0 || len(ipsBefore) == 0 {
		t.Fatalf("the installed deployment answers on nothing: %v / %v", before, ipsBefore)
	}

	if err := addHostsToDeployment(dir, "box.tail1234.ts.net,100.72.135.18"); err != nil {
		t.Fatalf("-add-host: %v", err)
	}

	after, ipsAfter, err := hostsInCertificate(filepath.Join(dir, "transport.crt"))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(after, ",")
	for _, want := range append(append([]string{}, before...), "box.tail1234.ts.net") {
		if !strings.Contains(joined, want) {
			t.Fatalf("%q is not in the certificate after adding a host: %v", want, after)
		}
	}
	seen := map[string]bool{}
	for _, ip := range ipsAfter {
		seen[ip.String()] = true
	}
	for _, want := range []string{"10.0.0.5", "100.72.135.18"} {
		if !seen[want] {
			t.Fatalf("%s is not in the certificate: %v", want, ipsAfter)
		}
	}

	// ★★ AND THE ANCHOR IS BYTE-IDENTICAL. Adding a name must not be a rotation — every device that already
	// adopted this keeps verifying, which is the entire difference between this and -force.
	anchorAfter, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(anchorBefore) != string(anchorAfter) {
		t.Fatal("the deployment anchor changed — every device that adopted the old one is now orphaned")
	}

	// The per-plane names follow the FIRST host. hostsInCertificate deliberately drops them (they are
	// derived, not given), so this reads the certificate itself — otherwise the assertion would be about the
	// filter rather than about what a client is offered.
	cert, err := readCertificate(filepath.Join(dir, "transport.crt"))
	if err != nil {
		t.Fatal(err)
	}
	offered := strings.Join(cert.DNSNames, ",")
	if !strings.Contains(offered, "agents."+before[0]) {
		t.Fatalf("the plane names no longer follow the deployment's first host: %v", cert.DNSNames)
	}
	// ★ AND THE ADDED NAME IS OFFERED WITH ITS OWN PLANES ABSENT, which is correct and worth pinning: a
	// tailnet machine name has no subdomains, so deriving "agents.<it>" would put a name in the certificate
	// that no client can resolve — measured from win-dev-1 on 2026-08-25.
	if strings.Contains(offered, "agents.box.tail1234.ts.net") {
		t.Fatal("plane names were derived from a secondary host, which nothing can resolve")
	}
}

// A deployment that does not exist cannot learn a name, and saying so is better than minting one.
func TestAddHostRefusesAnEmptyDirectory(t *testing.T) {
	err := addHostsToDeployment(t.TempDir(), "box.example.test")
	if err == nil || !strings.Contains(err.Error(), "holds no authorities") {
		t.Fatalf("adding a host to an uninstalled directory was allowed: %v", err)
	}
}
