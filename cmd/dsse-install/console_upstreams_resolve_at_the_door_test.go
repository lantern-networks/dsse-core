package main

import (
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Found 2026-11-04 by installing docs/plans/single-region.json on a fresh machine and signing in from a browser:
// the Console's upstreams named admin.<deployment> and <node>.admin.<deployment>, nothing on the machine
// resolved either, and every sign-in was a 502 that the page showed as "Invalid credentials". The plans with a
// declared node map already carried these names; the one-machine and three-region plans did not.
func TestTheConsoleResolvesItsOwnUpstreamsAtThisMachinesDoor(t *testing.T) {
	for _, file := range []string{"single-region.json", "three-regions.json"} {
		t.Run(file, func(t *testing.T) {
			p, err := LoadPlan("../../docs/plans/" + file)
			if err != nil {
				t.Fatal(err)
			}
			work := t.TempDir()
			source := filepath.Join(work, "source")
			installFromPlan(t, "../../docs/plans/"+file, source)
			dirs := map[string]string{p.foundingRegion().controlPlane().Name: source}
			for _, name := range p.MachineNames() {
				if _, done := dirs[name]; done {
					continue
				}
				archive := filepath.Join(work, name+".tgz")
				if err := carryPlanMachine(p, source, archive, name); err != nil {
					t.Fatal(err)
				}
				dir := unpackCarry(t, archive)
				if err := applyPlanToThisMachine(p, dir, name); err != nil {
					t.Fatal(err)
				}
				dirs[name] = dir
			}
			consoles := 0
			for machine, dir := range dirs {
				body := deploymentFileContents(t, dir, "docker-compose.yml")
				var parsed struct {
					Services map[string]struct {
						Environment map[string]string `yaml:"environment"`
						ExtraHosts  []string          `yaml:"extra_hosts"`
						Networks    map[string]struct {
							IPv4 string `yaml:"ipv4_address"`
						} `yaml:"networks"`
					} `yaml:"services"`
				}
				if err := yaml.Unmarshal([]byte(body), &parsed); err != nil {
					t.Fatalf("%s: compose does not parse: %v", machine, err)
				}
				console, ok := parsed.Services["dsse-console"]
				if !ok {
					continue
				}
				consoles++
				door := parsed.Services["dsse-edge"].Networks["default"].IPv4
				if door == "" {
					t.Fatalf("%s: the Console has no doorway beside it", machine)
				}
				hosts := map[string]string{}
				for _, entry := range console.ExtraHosts {
					name, at, _ := strings.Cut(entry, ":")
					hosts[name] = at
				}
				routes := deploymentFileContents(t, dir, "haproxy-edge.cfg")
				for _, key := range []string{"ADMIN_API_UPSTREAM", "CONTROL_API_UPSTREAM", "AUTH_API_UPSTREAM"} {
					value := console.Environment[key]
					_, def, found := strings.Cut(value, ":-")
					if !found {
						t.Fatalf("%s: %s = %q has no default", machine, key, value)
					}
					host := strings.TrimPrefix(strings.TrimSuffix(def, "}"), "https://")
					if i := strings.IndexAny(host, ":/"); i >= 0 {
						host = host[:i]
					}
					if hosts[host] != door {
						t.Errorf("%s: the Console's %s is %s, which its container maps to %q; want this machine's door %q",
							machine, key, host, hosts[host], door)
					}
					if !strings.Contains(routes, "req.ssl_sni -i "+host+" }") {
						t.Errorf("%s: the door on this machine does not route %s, which the Console's %s dials", machine, host, key)
					}
				}
			}
			if consoles == 0 {
				t.Fatal("no machine in the plan runs a Console")
			}
		})
	}
}

// A deployment that answers on an address reaches its control plane and Edge by container name, and a hosts
// entry for a container name would shadow the container network's own answer.
func TestTheConsoleNeedsNoHostsEntryForContainerNames(t *testing.T) {
	if got := consoleUpstreamNames("https://dsse-control-plane-a:9443", "https://dsse-edge-a:9443"); got != "" {
		t.Fatalf("container-name upstreams produced extra_hosts:\n%s", got)
	}
	if got := consoleUpstreamNames("https://10.0.0.5:9443"); got != "" {
		t.Fatalf("an address upstream produced extra_hosts:\n%s", got)
	}
	got := consoleUpstreamNames("https://admin.example.test", "https://region-a-edge-a.admin.example.test", "https://admin.example.test")
	if strings.Count(got, "\"admin.example.test:${DSSE_FRONT_DOOR_A:-10.77.0.5}\"") != 1 ||
		strings.Count(got, "\"region-a-edge-a.admin.example.test:${DSSE_FRONT_DOOR_A:-10.77.0.5}\"") != 1 {
		t.Fatalf("named upstreams were not mapped to the door once each:\n%s", got)
	}
}

// The verification -order prints must ask the Console, or a deployment nobody can sign in to reads green.
func TestTheOrderedVerificationAsksTheConsole(t *testing.T) {
	for _, file := range []string{"single-region.json", "three-regions.json", "one-region-three-independent-entries.json", "three-regions-multi-edge.json"} {
		p, err := LoadPlan("../../docs/plans/" + file)
		if err != nil {
			t.Fatal(err)
		}
		steps := p.InstallOrder("/opt/dsse", "/opt/dsse/plan.json")
		want := "-console https://" + p.PlaneNamesFor(p.foundingRegion().ID)["console"] + " "
		found := false
		for _, s := range steps {
			if strings.Contains(s.Do, "dsse-install -verify ") {
				found = true
				if !strings.Contains(s.Do, want) {
					t.Errorf("%s: -verify step does not ask the Console (%q):\n%s", file, want, s.Do)
				}
			}
		}
		if !found {
			t.Errorf("%s: -order printed no -verify step", file)
		}
	}
}
