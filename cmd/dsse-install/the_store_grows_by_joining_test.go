package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func planOfThree(t *testing.T) *Plan {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.json")
	body := `{
	  "deployment": "example.test",
	  "regions": [
	    {"id":"tokyo-a","founding":true,"holds_state":true,"machines":[
	      {"name":"node-tokyo-a","holds":["control-plane","edges"],"addresses":["10.0.0.1","10.0.0.2"],
	       "reachable":"node-tokyo-a.example.test","reachable_address":"203.0.113.1"}]},
	    {"id":"tokyo-c","holds_state":true,"machines":[
	      {"name":"node-tokyo-c","holds":["control-plane","edges"],"addresses":["10.0.1.1","10.0.1.2"],
	       "reachable":"node-tokyo-c.example.test","reachable_address":"203.0.113.2"}]},
	    {"id":"osaka","holds_state":true,"machines":[
	      {"name":"node-osaka","holds":["control-plane","edges"],"addresses":["10.0.2.1","10.0.2.2"],
	       "reachable":"node-osaka.example.test","reachable_address":"203.0.113.3"}]}
	  ]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPlan(path)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// ★★★ THE FOUNDING MEMBER STARTS A CLUSTER OF ONE AND THE OTHERS JOIN IT (2026-08-31).
//
// A static three-member bootstrap needs all three machines at once, and the install order is sequential: the
// founding region's control plane waits for a database whose Patroni waits for a quorum that needs machines
// nobody has built yet. So the founding region must be able to finish alone, which means it starts a cluster
// of one and each later region joins the cluster as it then is.
func TestEachStateBearingRegionNamesTheClusterAsItWillFindIt(t *testing.T) {
	p := planOfThree(t)
	for _, c := range []struct {
		machine string
		state   string
		members []string
		absent  []string
	}{
		{"node-tokyo-a", "new", []string{"dsse-store-tokyo-a=https://node-tokyo-a.example.test:12390"},
			[]string{"dsse-store-tokyo-c", "dsse-store-osaka"}},
		{"node-tokyo-c", "existing", []string{"dsse-store-tokyo-a=", "dsse-store-tokyo-c="},
			[]string{"dsse-store-osaka"}},
		{"node-osaka", "existing", []string{"dsse-store-tokyo-a=", "dsse-store-tokyo-c=", "dsse-store-osaka="}, nil},
	} {
		env, err := p.MachineEnvironment(c.machine)
		if err != nil {
			t.Fatalf("%s: %v", c.machine, err)
		}
		if got := env["DSSE_ETCD_INITIAL_CLUSTER_STATE"]; got != c.state {
			t.Errorf("%s bootstraps as %q, want %q", c.machine, got, c.state)
		}
		// ★ AND NEVER PLAINTEXT. This list only exists in a deployment whose store spans regions, and there
		// the peers carry which database is primary across whatever is between those regions.
		if strings.Contains(env["DSSE_ETCD_INITIAL_CLUSTER"], "http://") {
			t.Errorf("%s names a peer over plaintext: %q", c.machine, env["DSSE_ETCD_INITIAL_CLUSTER"])
		}
		// ★★★ PEERS MUST PRESENT A CERTIFICATE. That is the traffic that crosses a network between regions,
		// and encrypting it without asking who is calling leaves a peer anybody can be.
		if env["DSSE_ETCD_PEER_CLIENT_CERT_AUTH"] != "true" {
			t.Errorf("%s does not require a certificate from its peers", c.machine)
		}
		// ★★★ AND THE CLIENT ENDPOINT DELIBERATELY DOES NOT — A STATED GAP, PINNED SO IT STAYS VISIBLE
		// (2026-08-31, measured: Patroni could not start).
		//
		// Every private key this deployment mounts is 0600, which works because every container reading one
		// runs as root. The database image does not — Patroni is uid 101 — so the member key it was told to
		// present was unreadable, and the symptom was a permission error wearing a network error's clothes.
		//
		// The right fix is per-consumer client material owned by the uid that reads it. Until then the client
		// endpoint is encrypted and server-authenticated and asks for nothing, and this test says so out loud
		// rather than letting the relaxation become invisible. If somebody turns it back on, they must also
		// give Patroni a key it can read — and this failing is how they find out.
		if env["DSSE_ETCD_CLIENT_CERT_AUTH"] != "false" {
			t.Errorf("%s requires a client certificate: Patroni runs as uid 101 and cannot read a 0600 key, "+
				"so this starts nothing. Give it material it can read before asking for one.", c.machine)
		}
		if env["DSSE_ETCD_CLIENT_CERT"] != "" || env["DSSE_ETCD_CLIENT_KEY"] != "" {
			t.Errorf("%s points Patroni at a certificate it is not asked for and cannot read", c.machine)
		}
		if env["DSSE_ETCD_CLIENT_CACERT"] == "" {
			t.Errorf("%s does not verify the store it talks to: without the CA this is encryption to whoever "+
				"answered", c.machine)
		}
		if env["DSSE_ETCD_CLIENT_SCHEME"] != "https" {
			t.Errorf("%s reaches the store over %q, so Patroni talks plaintext to the thing that decides "+
				"which database is primary", c.machine, env["DSSE_ETCD_CLIENT_SCHEME"])
		}
		cluster := env["DSSE_ETCD_INITIAL_CLUSTER"]
		for _, want := range c.members {
			if !strings.Contains(cluster, want) {
				t.Errorf("%s does not name %s in its cluster: %q", c.machine, want, cluster)
			}
		}
		for _, no := range c.absent {
			if strings.Contains(cluster, no) {
				t.Errorf("%s names %s, which does not exist yet when it starts: %q", c.machine, no, cluster)
			}
		}
		// ★ ITS OWN NAME IS THE CLUSTER'S, NOT THIS HOST'S. Three regions rendering one file would otherwise
		// all call themselves dsse-store-a.
		if env["DSSE_ETCD_A_NAME"] == "" || env["DSSE_ETCD_A_NAME"] == "dsse-store-a" {
			t.Errorf("%s calls its member %q", c.machine, env["DSSE_ETCD_A_NAME"])
		}
		// ★ AND IT PUBLISHES THE PEER PORT. Without it the others can be told where it is and never reach it.
		if env["DSSE_ETCD_A_PEER_PUBLISH"] == "" || env["DSSE_ETCD_A_PEER_ADVERTISE"] == "" {
			t.Errorf("%s does not publish or advertise a peer address", c.machine)
		}
	}
}

// ★ AND PATRONI IS TOLD ABOUT EVERY MEMBER, not about three ports on one machine.
func TestPatroniIsPointedAtEveryRegionsMember(t *testing.T) {
	p := planOfThree(t)
	env, err := p.MachineEnvironment("node-osaka")
	if err != nil {
		t.Fatal(err)
	}
	hosts := env["DSSE_ETCD_HOSTS"]
	for _, want := range []string{"node-tokyo-a.example.test:12379", "node-tokyo-c.example.test:12379", "node-osaka.example.test:12379"} {
		if !strings.Contains(hosts, want) {
			t.Errorf("Patroni is not told about %s: %q", want, hosts)
		}
	}
	if strings.Contains(hosts, ":12380") || strings.Contains(hosts, ":12381") {
		t.Errorf("Patroni is still pointed at three ports on one machine: %q", hosts)
	}
}

// ★★★ AN EDGE IS TOLD WHERE LEADERSHIP CAN BE, AND WHERE TO SHIP (2026-08-31, measured).
//
// start-edge.sh has read DSSE_CP_ENDPOINTS since 2026-08-25 and turns it into -config-source-endpoints, which
// makes the Edge probe each region's GET /leader and pull from whichever answers. Nothing wrote the data half
// and the compose file passed neither, so every Edge used one URL: its own region's door. In a region that
// JOINS, the control planes behind that door are warm standbys, so it had nothing to route to — and what the
// Edge could not deliver it kept, which is the symptom start-edge.sh names beside those variables.
//
// ★ AND A DOOR COULD NOT HAVE FIXED IT. Every region answers /leader through its own front door, which
// forwards to whoever leads, so a health check there cannot tell a region that LEADS from one that merely
// knows where the leader is. The Edge asking each region BY NAME can.
func TestAnEdgeIsToldWhereLeadershipCanBeAndWhereToShip(t *testing.T) {
	p := planOfThree(t)
	for _, machine := range []string{"node-tokyo-a", "node-tokyo-c", "node-osaka"} {
		env, err := p.MachineEnvironment(machine)
		if err != nil {
			t.Fatal(err)
		}
		read, write := env["DSSE_CP_ENDPOINTS"], env["DSSE_CP_DATA_ENDPOINTS"]
		for _, id := range []string{"tokyo-a", "tokyo-c", "osaka"} {
			if !strings.Contains(read, id+"=https://admin."+id+".") {
				t.Errorf("%s is not told it can read from %s: %q", machine, id, read)
			}
			// ★ THE WRITE ADDRESS IS A DIFFERENT NAME OF THE SAME REGION, not the same one.
			if !strings.Contains(write, id+"=https://authority."+id+".") {
				t.Errorf("%s is not told where to ship to %s: %q", machine, id, write)
			}
		}
		if env["DSSE_CP_HOME"] == "" {
			t.Errorf("%s names no home region, so every read starts by asking somewhere else", machine)
		}
	}
}

// ★★★ CLOSING THE BREAK-GLASS CREDENTIAL RESTARTS THE EDGES TOO (2026-08-31, measured: it did not).
//
// The restart is what closes a credential that authorises as owner and attributes every act to nobody. It
// also changes what the FLEET presents — and an Edge still holding the old one is answered 401 on every pull
// while staying healthy on every screen: it keeps serving what it booted with and never learns anything
// again. The founding region's Edges sat there, knowing none of the connectors the other regions had
// registered, and the deployment's own compose file has said this beside the same act since 2026-08-26.
func TestClosingTheBreakGlassCredentialRestartsTheEdges(t *testing.T) {
	p := planOfThree(t)
	found := false
	for _, step := range p.InstallOrder("/opt/dsse", "/tmp/plan.json") {
		if !strings.Contains(step.Do, "--force-recreate") || !strings.Contains(step.Do, "dsse-control-plane-a") {
			continue
		}
		found = true
		// ★ THE EDGES ARE COUNTED FROM THE COMPOSE FILE, NOT LISTED HERE (2026-09-02). This named
		// dsse-edge-a and dsse-edge-b, and when the operator retired the second Edge on a machine the
		// assertion outlived the thing it described: it went on demanding a restart of a service the
		// deployment no longer defines, while a NEW Edge service would slip past it unnamed. What the step
		// must restart is every Edge this deployment actually has.
		for _, svc := range edgeServicesInComposeFile(t) {
			if !strings.Contains(step.Do, svc) {
				t.Errorf("the step that closes the break-glass credential does not restart %s, so it is "+
					"answered 401 on every pull afterwards and nothing says so:\n  %s", svc, step.Do)
			}
		}
	}
	if !found {
		t.Fatal("the order no longer closes the break-glass credential with a restart")
	}
}

// edgeServicesInComposeFile is every Edge service the generated compose file defines — asked of the file so
// that a shape change cannot leave an assertion describing a deployment that no longer exists.
func edgeServicesInComposeFile(t *testing.T) []string {
	t.Helper()
	body, err := composeBodyFor(t.TempDir(), foundingShape)
	if err != nil {
		t.Fatalf("render the compose file: %v", err)
	}
	var edges []string
	for _, line := range strings.Split(body, "\n") {
		name := strings.TrimSuffix(strings.TrimSpace(line), ":")
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") &&
			strings.HasSuffix(strings.TrimSpace(line), ":") &&
			strings.HasPrefix(name, "dsse-edge") && !strings.Contains(name, " ") {
			edges = append(edges, name)
		}
	}
	if len(edges) == 0 {
		t.Fatal("the generated compose file defines no Edge at all")
	}
	return edges
}
