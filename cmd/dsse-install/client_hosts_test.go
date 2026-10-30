package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestThreeNodeMintedCertificatesCoverRootPlaneNames(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.Names = nil // Operators must not have to repeat the root planes as aliases.
	work := t.TempDir()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	planFile := filepath.Join(work, "plan.json")
	if err := os.WriteFile(planFile, b, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(work, "deployment")
	installFromPlan(t, planFile, dir)
	for _, file := range []string{"management.crt", "transport.crt"} {
		body, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(body)
		if block == nil {
			t.Fatal("missing certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		for _, plane := range []string{"admin", "authority", "agents", "console", "recovery"} {
			name := plane + "." + p.Deployment
			if err := cert.VerifyHostname(name); err != nil {
				t.Errorf("%s cannot serve %s: %v", file, name, err)
			}
		}
	}
}

func TestClientHostsUseOneEntryIncludingOwnedPortalsAndTenantNames(t *testing.T) {
	p := threeNodesOneRegionPlan()
	block, err := p.RenderClientHosts("203.0.113.42", []string{"freshmomiji", "freshkaede"})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseClientHosts(block)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, entry := range entries {
		names[entry.Name] = true
		if !entry.IP.Equal(net.ParseIP("203.0.113.42")) {
			t.Fatalf("per-Node address leaked: %+v", entry)
		}
	}
	// Written independently of CertificateNames: these are the names clients use.
	for _, name := range []string{
		"example.test", "admin.example.test", "agents.example.test", "recovery.example.test",
		"console.example.test", "authority.example.test", "admin.kiri.example.test",
		"node-b.example.test", "portal-c.example.test", "kiri-node-b-edge-a.admin.example.test",
		"freshmomiji.example.test", "enrol.freshmomiji.example.test", "recovery.freshkaede.example.test",
	} {
		if !names[name] {
			t.Errorf("client cannot resolve %s", name)
		}
	}
	again, err := p.RenderClientHosts("203.0.113.42", []string{"freshkaede", "freshmomiji"})
	if err != nil || again != block {
		t.Fatal("regeneration is not deterministic")
	}
	// A failover changes which Node owns the entry, not the client map.
	p.Regions[0].Machines[0].ReachableAddress = "10.20.0.9"
	again, err = p.RenderClientHosts("203.0.113.42", []string{"freshmomiji", "freshkaede"})
	if err != nil || again != block {
		t.Fatal("client map depends on a private Node address")
	}
}

func TestClientHostsRejectAmbiguousBlocksAndInjection(t *testing.T) {
	p := threeNodesOneRegionPlan()
	if _, err := p.RenderClientHosts("203.0.113.42", []string{"label\n127.0.0.1 injected.test"}); err == nil {
		t.Fatal("tenant name injection accepted")
	}
	for _, ip := range []string{"", "not-an-ip", "0.0.0.0", "127.0.0.1", "224.0.0.1"} {
		if _, err := p.RenderClientHosts(ip, nil); err == nil {
			t.Fatalf("invalid entry %q accepted", ip)
		}
	}
	p.Names = []string{"bad alias.example.test"}
	if _, err := p.RenderClientHosts("203.0.113.42", nil); err == nil {
		t.Fatal("invalid plan alias accepted")
	}
	p.Names = nil
	block, err := p.RenderClientHosts("203.0.113.42", nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{
		block + block,
		strings.Replace(block, "# END DSSE HOSTS example.test", "# END DSSE HOSTS other.test", 1),
		strings.Replace(block, "203.0.113.42 admin.example.test", "203.0.113.43 admin.example.test", 1),
		strings.Replace(block, "# END DSSE HOSTS example.test", "", 1),
	}
	for _, input := range bad {
		if _, err := parseClientHosts(input); err == nil {
			t.Fatal("malformed or multi-entry hosts block accepted")
		}
	}
}

func TestClientHostsVerifyRequiresCompletePlanAndCurrentTenantSet(t *testing.T) {
	p := threeNodesOneRegionPlan()
	labels := []string{"freshmomiji", "freshkaede"}
	block, err := p.RenderClientHosts("203.0.113.42", labels)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseClientHosts(block)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.validateClientHostEntries(entries, labels); err != nil {
		t.Fatal(err)
	}
	if err := p.validateClientHostEntries(entries[:len(entries)-1], labels); err == nil {
		t.Fatal("incomplete name coverage accepted")
	}
	if err := p.validateClientHostEntries(entries, []string{"oldtenant"}); err == nil {
		t.Fatal("stale tenant name set accepted")
	}
}
