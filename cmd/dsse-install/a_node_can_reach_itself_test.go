package main

import (
	"path/filepath"
	"testing"
)

// ★★★ A DEPLOYMENT HARDENED THE WAY THE PROCEDURE ASKS CANNOT BE CHECKED AT ALL (2026-08-27, measured on the
// AWS lab, one component per machine). The lab publishes only 22 and 443 to the world and binds every admin
// surface to loopback — which is the right posture and is what the installer's own defaults become once an
// operator narrows them. Standing ON the Edge's machine, the only address that reaches its admin port is
// 127.0.0.1, and the certificate the node presents refuses it:
//
//	-edge-admin https://127.0.0.1:9443
//	FAIL the Edge answers — x509: certificate is valid for 10.77.0.10, not 127.0.0.1
//
// There is then NO address anywhere from which -verify can ask that node a question: not from another machine
// (the port is loopback) and not from its own (the name is refused). The deployment is fine and unverifiable.
//
// The reasoning is the one already written beside the compose service names in main.go: the names a node is
// reached by from INSIDE are also names, the operator never says them because they are not what the
// deployment answers on from outside, and leaving them out produces a deployment that works one way and not
// the other — repaired only by re-minting, which orphans every anchor already distributed.
func TestANodeCertificateNamesTheLoopbackItIsReachedOnFromItsOwnMachine(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	for _, leaf := range []string{"management", "transport", "edge-identity"} {
		chain := readChain(t, filepath.Join(dir, leaf+".crt"))
		if len(chain) == 0 {
			t.Fatalf("%s.crt holds no certificate", leaf)
		}
		for _, self := range []string{"localhost", "127.0.0.1", "::1"} {
			if err := chain[0].VerifyHostname(self); err != nil {
				t.Errorf("%s cannot be reached at %s from its own machine — the only address left once the "+
					"admin surfaces are bound to loopback: %v", leaf, self, err)
			}
		}
	}
}

// ★ AND THE LOOPBACK IS NOT WHAT THE DEPLOYMENT IS CALLED. It is added to what a certificate ANSWERS to, not
// to what the deployment is named after: a CN of "localhost", or plane names derived from it, is the defect
// main.go already warns about at the end of an install — a deployment that cannot span regions because every
// name resolves to whoever asks.
func TestTheLoopbackIsNotWhatTheDeploymentIsNamedAfter(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	chain := readChain(t, filepath.Join(dir, "management.crt"))
	if cn := chain[0].Subject.CommonName; cn == "localhost" {
		t.Fatalf("the deployment is named after its own loopback (CN=%q)", cn)
	}
	for _, n := range chain[0].DNSNames {
		if n == "agents.localhost" || n == "admin.localhost" || n == "recovery.localhost" {
			t.Fatalf("a plane name was derived from the loopback: %q", n)
		}
	}
	// Control: the name the operator actually gave is still what this certificate is for, so the assertions
	// above are about the loopback and not about a certificate that names nothing.
	if err := chain[0].VerifyHostname("dsse.example"); err != nil {
		t.Fatalf("the name the operator gave is no longer in the certificate: %v", err)
	}
}

// ★★★ AND -add-host IS THE REPAIR FOR A DEPLOYMENT THAT WAS MINTED BEFORE THIS. It re-issues the leaves from
// the authorities already on disk and touches neither, so every anchor already distributed keeps verifying —
// which is the only reason a running lab can be repaired at all rather than rebuilt.
func TestAddHostRepairsADeploymentThatCannotReachItself(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	before := readChain(t, filepath.Join(dir, "management.crt"))[0]
	rootBefore := readCert(t, filepath.Join(dir, "root.crt"))

	if err := addHostsToDeployment(dir, "extra.example"); err != nil {
		t.Fatalf("-add-host: %v", err)
	}
	after := readChain(t, filepath.Join(dir, "management.crt"))[0]
	rootAfter := readCert(t, filepath.Join(dir, "root.crt"))

	if !rootBefore.Equal(rootAfter) {
		t.Fatal("-add-host changed the anchor, which orphans every device that adopted the old one")
	}
	for _, self := range []string{"localhost", "127.0.0.1"} {
		if err := after.VerifyHostname(self); err != nil {
			t.Errorf("after -add-host the node still cannot be reached at %s from its own machine: %v", self, err)
		}
	}
	if err := after.VerifyHostname("extra.example"); err != nil {
		t.Errorf("-add-host did not add the name it was given: %v", err)
	}
	if err := after.VerifyHostname("dsse.example"); err != nil {
		t.Errorf("-add-host dropped a name the deployment already answered on: %v", err)
	}
	if before.SerialNumber.Cmp(after.SerialNumber) == 0 {
		t.Fatal("-add-host reported success and re-issued nothing")
	}

	// ★ AND THE LOOPBACK IS NOT READ BACK AS SOMETHING THE OPERATOR ASKED FOR. hostsInCertificate drops the
	// names this installer DERIVES so they are not fed back in as intent; the loopback is one of them, and
	// without this the printed list of what the deployment answers on grows a name nobody gave it.
	names, ips, err := hostsInCertificate(filepath.Join(dir, "management.crt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n == "localhost" {
			t.Fatalf("the loopback is reported as a name the operator gave: %v", names)
		}
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			t.Fatalf("the loopback is reported as an address the operator gave: %v", ips)
		}
	}
	// Control: the names they DID give are still read back, so the assertions above are about the loopback.
	if len(names) == 0 {
		t.Fatal("nothing at all was read back as operator intent")
	}
}
