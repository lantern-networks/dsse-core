package main

import (
	"strings"
	"testing"
)

const seed2 = "osaka=https://agents.osaka.hikari.lab;tokyo=https://agents.tokyo.hikari.lab"

// ★★★ THE DOCUMENT THAT ENABLES FAILOVER MUST NOT BE REACHABLE ONLY THROUGH THE REGION FAILOVER SURVIVES
// (measured on win-dev-1 with the osaka doorway stopped: the device never learned it could fail over and
// stayed dark for the whole outage).
func TestThePostureIsAskedOfEveryRegionTheProfileSeeded(t *testing.T) {
	plan := posturePlan("", "agents.osaka.hikari.lab:443", seed2)
	if len(plan) != 2 {
		t.Fatalf("plan = %d endpoint(s), want the home one and the other region: %+v", len(plan), plan)
	}
	// The home address is first: the ordinary case must not pay for the outage case.
	if plan[0].HostPort != "agents.osaka.hikari.lab:443" {
		t.Fatalf("the address already in force is not tried first: %+v", plan)
	}
	if plan[1].HostPort != "agents.tokyo.hikari.lab:443" || plan[1].Region != "tokyo" {
		t.Fatalf("the second region is missing or unlabelled: %+v", plan)
	}
	// The name to verify is the host, never the host:port.
	for _, e := range plan {
		if strings.Contains(e.ServerName, ":") {
			t.Fatalf("server name carries a port: %q", e.ServerName)
		}
	}
}

// The home region appears in the seed too; asking it twice would double the cost of the ordinary case and
// double the log lines of the outage case.
func TestTheHomeRegionIsNotAskedTwice(t *testing.T) {
	plan := posturePlan("", "agents.osaka.hikari.lab:443", seed2)
	seen := map[string]int{}
	for _, e := range plan {
		seen[e.HostPort]++
	}
	for h, n := range seen {
		if n != 1 {
			t.Fatalf("%s appears %d times", h, n)
		}
	}
}

// ★ THE DOORS CARRY NO PORT since the agent plane folded onto 443, and a dial target without one is not a
// dial target. This is the same normalisation that cost the macOS side its whole transport.
func TestAPortlessDoorBecomes443(t *testing.T) {
	plan := posturePlan("", "", "tokyo=https://agents.tokyo.hikari.lab")
	if len(plan) != 1 || plan[0].HostPort != "agents.tokyo.hikari.lab:443" {
		t.Fatalf("%+v", plan)
	}
	if plan[0].BaseURL != "https://agents.tokyo.hikari.lab:443" {
		t.Fatalf("base = %q", plan[0].BaseURL)
	}
	// An explicit port is kept.
	if p := posturePlan("", "", "x=https://edge.example:18543"); p[0].HostPort != "edge.example:18543" {
		t.Fatalf("%+v", p)
	}
}

// Somebody who names an address is not asking for a search.
func TestAnExplicitPolicyURLIsTheOnlyCandidate(t *testing.T) {
	plan := posturePlan("https://policy.example:9443", "agents.osaka.hikari.lab:443", seed2)
	if len(plan) != 1 || plan[0].HostPort != "policy.example:9443" {
		t.Fatalf("an operator's explicit address was joined by a search: %+v", plan)
	}
}

// No seed at all is the single-region deployment, unchanged: one candidate, the one already in force.
func TestWithNoSeedNothingChanges(t *testing.T) {
	plan := posturePlan("", "agents.osaka.hikari.lab:443", "")
	if len(plan) != 1 || plan[0].HostPort != "agents.osaka.hikari.lab:443" {
		t.Fatalf("%+v", plan)
	}
	if len(posturePlan("", "", "")) != 0 {
		t.Fatal("with nothing to go on the plan must be empty, not a guess")
	}
}

// IPv6 literals must not be mangled into a host with a stray colon.
func TestAnIPv6LiteralKeepsItsBrackets(t *testing.T) {
	p := posturePlan("", "[2001:db8::1]", "")
	if len(p) != 1 || p[0].HostPort != "[2001:db8::1]:443" || p[0].ServerName != "2001:db8::1" {
		t.Fatalf("%+v", p)
	}
	q := posturePlan("", "[2001:db8::1]:18543", "")
	if q[0].HostPort != "[2001:db8::1]:18543" {
		t.Fatalf("%+v", q)
	}
}
