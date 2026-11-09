package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Security review S4 (2026-11-07). The one-host deployment's consensus store listened in the clear because its
// container network never leaves the machine. The Edge on that machine dials outward for every steered device,
// so the member that decides which database is primary now speaks TLS and asks for a client certificate like
// every member of a spanning store.
func TestAOneHostStoreAsksForACertificate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	body := `{
	  "deployment": "example.test",
	  "regions": [
	    {"id":"tokyo","founding":true,"holds_state":true,"machines":[
	      {"name":"node-tokyo","holds":["control-plane","edges"],"addresses":["10.0.0.1","10.0.0.2"],
	       "reachable":"node-tokyo.example.test","reachable_address":"203.0.113.1"}]}
	  ]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	env, err := p.MachineEnvironment("node-tokyo")
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"DSSE_ETCD_CLIENT_CERT_AUTH":      "true",
		"DSSE_ETCD_PEER_CLIENT_CERT_AUTH": "true",
		"DSSE_ETCD_CLIENT_SCHEME":         "https",
		"DSSE_ETCD_LISTEN_CLIENT_URLS":    "https://0.0.0.0:2379",
		"DSSE_ETCD_A_ADVERTISE":           "https://node-tokyo.example.test:12379",
		"DSSE_ETCD_INITIAL_CLUSTER_STATE": "new",
	} {
		if got := env[key]; got != want {
			t.Errorf("%s = %q, want %q: the one-host store is still in the clear", key, got, want)
		}
	}
	if env["DSSE_ETCD_INITIAL_CLUSTER"] == "" {
		t.Error("the one-host member names no cluster")
	}
}

// Review R1: the founding region holds state whether or not the plan says so, and a deployment generated
// without a plan (-host) has a store too. Both must speak TLS.
func TestAFoundingRegionThatDoesNotDeclareStateStillSpeaksTLS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	body := `{
	  "deployment": "example.test",
	  "regions": [
	    {"id":"tokyo","founding":true,"machines":[
	      {"name":"node-tokyo","holds":["control-plane","edges"],"addresses":["10.0.0.1","10.0.0.2"],
	       "reachable":"node-tokyo.example.test","reachable_address":"203.0.113.1"}]}
	  ]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	env, err := p.MachineEnvironment("node-tokyo")
	if err != nil {
		t.Fatal(err)
	}
	if env["DSSE_ETCD_CLIENT_CERT_AUTH"] != "true" || env["DSSE_ETCD_CLIENT_SCHEME"] != "https" || env["DSSE_ETCD_A_ADVERTISE"] != "https://node-tokyo.example.test:12379" {
		t.Fatalf("a founding region without holds_state generated a store in the clear: %q %q %q",
			env["DSSE_ETCD_CLIENT_CERT_AUTH"], env["DSSE_ETCD_CLIENT_SCHEME"], env["DSSE_ETCD_A_ADVERTISE"])
	}
}

func TestADeploymentGeneratedWithoutAPlanHasAStoreThatSpeaksTLS(t *testing.T) {
	dir := t.TempDir()
	if err := writeEnvironment(dir, []string{"review.example.test"}, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"DSSE_ETCD_HOSTS=\"'dsse-store-a:2379'\"",
		"DSSE_ETCD_CLIENT_CERT_AUTH='true'",
		"DSSE_ETCD_PEER_CLIENT_CERT_AUTH='true'",
		"DSSE_ETCD_CLIENT_SCHEME='https'",
		"DSSE_ETCD_A_ADVERTISE='https://dsse-store-a:2379'",
		"DSSE_ETCD_INITIAL_CLUSTER='dsse-store-a=https://dsse-store-a:2380'",
		"DSSE_ETCD_CLIENT_CERT='/run/dsse-postgres-tls/store-client.pem'",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("deployment.env generated without a plan lacks %s", want)
		}
	}
}

// Review R2: the doorway states the browser's address to the Console, and the Console is told which doors
// to believe.
func TestTheDoorwayStatesTheBrowsersAddressToTheConsole(t *testing.T) {
	backend, err := oneRegionThreeNodesConsoleBackends("10.20.0.1:19544,10.20.0.2:19544,10.20.0.3:19544", "console.example.test", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(backend, "send-proxy") != 3 {
		t.Fatalf("the three-node Console backend does not send the PROXY header to every Console:\n%s", backend)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(path, []byte(`{
	  "profile": "one-region-three-nodes",
	  "deployment": "example.test",
	  "regions": [{"id":"kiri","founding":true,"holds_state":true,"machines":[
	    {"name":"node-a","portal":"portal-a.example.test","failure_domain":"rack-a","holds":["control-plane","edges"],"addresses":["10.20.0.1"],"reachable":"node-a.example.test","reachable_address":"10.20.0.1"},
	    {"name":"node-b","portal":"portal-b.example.test","failure_domain":"rack-b","holds":["control-plane","edges"],"addresses":["10.20.0.2"],"reachable":"node-b.example.test","reachable_address":"10.20.0.2"},
	    {"name":"node-c","portal":"portal-c.example.test","failure_domain":"rack-c","holds":["control-plane","edges"],"addresses":["10.20.0.3"],"reachable":"node-c.example.test","reachable_address":"10.20.0.3"}
	  ]}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	env, err := p.MachineEnvironment("node-b")
	if err != nil {
		t.Fatal(err)
	}
	doors := env["DSSE_CONSOLE_TRUSTED_FRONT_DOORS"]
	for _, want := range []string{env["DSSE_FRONT_DOOR_A"], "10.20.0.1", "10.20.0.3"} {
		if !strings.Contains(doors, want) {
			t.Errorf("node-b's Console does not believe door %s: %q", want, doors)
		}
	}
	if strings.Contains(doors, "10.20.0.2") {
		t.Errorf("node-b's Console lists its own machine as a foreign door: %q", doors)
	}
}

// Re-review RR1: in the three-Region multi-edge profile every Region's door lists every Region's Console and
// states the browser's address to it, so a Console believes the other Regions' control-plane machines too.
func TestAThreeRegionConsoleBelievesEveryRegionsDoor(t *testing.T) {
	p, err := LoadPlan(filepath.Join("..", "..", "docs", "plans", "three-regions-multi-edge.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, region := range p.Regions {
		cp := region.controlPlane()
		env, err := p.MachineEnvironment(cp.Name)
		if err != nil {
			t.Fatal(err)
		}
		doors := env["DSSE_CONSOLE_TRUSTED_FRONT_DOORS"]
		if !strings.Contains(doors, env["DSSE_FRONT_DOOR_A"]) {
			t.Errorf("%s: its own door is missing from %q", cp.Name, doors)
		}
		for _, other := range p.Regions {
			if other.ID == region.ID {
				continue
			}
			for _, a := range dedupeSorted(other.controlPlane().Addresses, other.controlPlane().reachableAt()) {
				if !strings.Contains(doors, a) {
					t.Errorf("%s: the door of %s (%s) is missing from %q", cp.Name, other.ID, a, doors)
				}
			}
		}
	}
	frontEnv := map[string]string{"DSSE_CP_A_BIND": "10.0.0.1", "DSSE_CONSOLE_BACKENDS": "10.0.0.1:19544,10.0.1.1:19544,10.0.2.1:19544"}
	_ = frontEnv
	admin, _, console, err := singleCPMultiEdgeBackends(map[string]string{"DSSE_CP_A_BIND": "10.0.0.1"}, "admin.example.test", "console.example.test")
	if err != nil {
		t.Fatal(err)
	}
	_ = admin
	if !strings.Contains(console, "send-proxy") {
		t.Fatalf("the single-CP multi-edge door does not state the browser's address to the Console:\n%s", console)
	}
}
