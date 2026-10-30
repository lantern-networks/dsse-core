package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestThreeRegionsKeepOneDoorPerRegion(t *testing.T) {
	p, err := LoadPlan("../../docs/plans/three-regions.json")
	if err != nil {
		t.Fatal(err)
	}
	want := "region-a=https://agents.region-a.example.test;region-b=https://agents.region-b.example.test;region-c=https://agents.region-c.example.test"
	if got := p.RegionEndpoints(); got != want {
		t.Fatalf("three-region endpoints=%q, want %q", got, want)
	}
	env, err := p.MachineEnvironment("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if env["DSSE_REGION_ENDPOINTS"] != want || env["DSSE_CP_QUORUM_ENDPOINTS"] != "" || env[edgeBackendsKey] != "" || env["DSSE_TOPOLOGY_PROFILE"] != "" {
		t.Fatalf("legacy machine environment changed: regions=%q quorum=%q backends=%q profile=%q",
			env["DSSE_REGION_ENDPOINTS"], env["DSSE_CP_QUORUM_ENDPOINTS"], env[edgeBackendsKey], env["DSSE_TOPOLOGY_PROFILE"])
	}
}

func TestOneRegionThreeNodesWithoutExternalEntryPublishesThreeDoors(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.Regions[0].Entry = nil
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	got := p.RegionEndpoints()
	for _, name := range []string{"agents.node-a.example.test", "agents.node-b.example.test", "agents.node-c.example.test"} {
		if !strings.Contains(got, "kiri=https://"+name) {
			t.Fatalf("missing %s from %q", name, got)
		}
		found := false
		for _, san := range p.CertificateNames() {
			if san == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing certificate name %s", name)
		}
	}
	if strings.Count(got, "kiri=") != 3 {
		t.Fatalf("want three independent doors: %q", got)
	}
	env, err := p.MachineEnvironment("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if env["ADMIN_CONSOLE_ORIGINS"] != "https://console.kiri.example.test" {
		t.Fatalf("console origins=%q", env["ADMIN_CONSOLE_ORIGINS"])
	}
	p.Regions[0].Machines[1].Reachable = p.Regions[0].Machines[0].Reachable
	if err := p.Validate(); err == nil {
		t.Fatal("two Node doors with the same TLS/DNS name accepted")
	}
}

func TestEveryIndependentDoorHasTheSameThreeEdgeCandidates(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.Regions[0].Entry = nil
	for _, machine := range p.Regions[0].Machines {
		env, err := p.MachineEnvironment(machine.Name)
		if err != nil {
			t.Fatal(err)
		}
		backends := strings.Split(env[edgeBackendsKey], ",")
		if len(backends) != 3 || backends[0] != "dsse-edge-a:8443" || env["DSSE_EDGE_BALANCE"] != "leastconn" {
			t.Fatalf("%s: backends=%v balance=%q", machine.Name, backends, env["DSSE_EDGE_BALANCE"])
		}
		for _, peer := range p.Regions[0].Machines {
			if peer.Name == machine.Name {
				continue
			}
			want := peer.reachableAt() + ":8443"
			if !strings.Contains(env[edgeBackendsKey], want) {
				t.Fatalf("%s: missing peer Edge %s in %v", machine.Name, want, backends)
			}
		}
	}
}

func TestQuorumAndCPOnlyDoorIgnoreEdgeOnlyMachine(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.Regions[0].Machines = append(p.Regions[0].Machines,
		PlanMachine{Name: "edge-only", Holds: heldComponents{"edges"}, Addresses: []string{"10.20.0.4"}, Reachable: "edge-only.example.test"})
	env, err := p.MachineEnvironment("node-a")
	if err != nil {
		t.Fatal(err)
	}
	var quorum []string
	if err := json.Unmarshal([]byte(env["DSSE_CP_QUORUM_ENDPOINTS"]), &quorum); err != nil {
		t.Fatal(err)
	}
	if len(quorum) != 3 || strings.Contains(env["DSSE_CP_QUORUM_ENDPOINTS"], "edge-only") || strings.Contains(env["DSSE_ETCD_HOSTS"], "edge-only") {
		t.Fatalf("quorum=%v etcd=%q", quorum, env["DSSE_ETCD_HOSTS"])
	}
	p.Regions[0].Machines[0].Holds = heldComponents{"control-plane"}
	env, err = p.MachineEnvironment("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(env[edgeBackendsKey], "dsse-edge-a") || !strings.Contains(env[edgeBackendsKey], "10.20.0.2") {
		t.Fatalf("CP-only door backends=%q", env[edgeBackendsKey])
	}
	if got := edgeFleetServersOnMachine(nil, "", false); got != "" {
		t.Fatalf("CP-only door invented local Edge: %q", got)
	}
}

func TestClientHostsGiveEveryAgentDoorItsOwnAddress(t *testing.T) {
	p := threeNodesOneRegionPlan()
	p.Regions[0].Entry = nil
	ipByNode := map[string]string{"node-a": "203.0.113.10", "node-b": "203.0.113.11", "node-c": "203.0.113.12"}
	block, err := p.RenderClientHostsWithNodeIPs("203.0.113.10", ipByNode, nil)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseClientHosts(block)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.validateClientHostEntries(entries, nil); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, ep := range entries {
		got[ep.Name] = ep.IP.String()
	}
	for node, ip := range ipByNode {
		name := "agents." + node + ".example.test"
		if got[name] != ip {
			t.Fatalf("%s=%q, want %s", name, got[name], ip)
		}
	}
	if got["agents.example.test"] != ipByNode["node-a"] {
		t.Fatalf("shared name=%q", got["agents.example.test"])
	}
	for i := range entries {
		if entries[i].Name == "agents.node-b.example.test" {
			entries[i].IP = net.ParseIP("203.0.113.10")
			break
		}
	}
	if err := p.validateClientHostEntries(entries, nil); err == nil {
		t.Fatal("one public address for two agent doors accepted")
	}
}
