package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A browser may coalesce HTTP/2 requests for two origins on one IP when the
// first origin's TLS leaf covers both. The Console leaf must never make that
// possible for a separately routed Browser Portal.
func TestPlannedConsoleCertificateCannotCoverBrowserPortals(t *testing.T) {
	p := threeNodesOneRegionPlan()
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
	installFromPlan(t, planPath, dir)
	management, err := readCertificate(filepath.Join(dir, "management.crt"))
	if err != nil {
		t.Fatal(err)
	}
	transport, err := readCertificate(filepath.Join(dir, "transport.crt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, portal := range p.BrowserPortalNames() {
		if management.VerifyHostname(portal) == nil {
			t.Fatalf("Console leaf covers Portal %q", portal)
		}
		if err := transport.VerifyHostname(portal); err != nil {
			t.Fatalf("transport fallback lost Portal %q: %v", portal, err)
		}
	}
	if err := management.VerifyHostname(p.PlaneNamesFor(p.Regions[0].ID)["console"]); err != nil {
		t.Fatalf("Console leaf lost its own name: %v", err)
	}
	anchorBefore, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil {
		t.Fatal(err)
	}
	// The existing -add-host narrowing guard requires the three node-specific
	// agent aliases to be restated for this topology.
	if err := addHostsToDeployment(dir, "extra.example.test,agents.node-a.example.test,agents.node-b.example.test,agents.node-c.example.test"); err != nil {
		t.Fatal(err)
	}
	management, err = readCertificate(filepath.Join(dir, "management.crt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, portal := range p.BrowserPortalNames() {
		if management.VerifyHostname(portal) == nil {
			t.Fatalf("-add-host reintroduced Portal %q into Console leaf", portal)
		}
	}
	if err := management.VerifyHostname("extra.example.test"); err != nil {
		t.Fatalf("-add-host omitted the requested name: %v", err)
	}
	anchorAfter, err := os.ReadFile(filepath.Join(dir, "deployment-anchor.pem"))
	if err != nil || !bytes.Equal(anchorBefore, anchorAfter) {
		t.Fatal("-add-host replaced the deployment trust anchor")
	}
}

func TestInvalidBrowserPortalRecordFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, browserPortalNamesFile), []byte(`["portal.example.test","*.example.test"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBrowserPortalNames(dir); err == nil {
		t.Fatal("invalid Portal name record was accepted")
	}
}
