package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ★★★ A REGION THAT KEEPS NO DATABASE IS NOT SOMEWHERE LEADERSHIP CAN MOVE (2026-08-27, measured on a
// deployment presented as two regions).
//
// The second region had NO Postgres at all — its control plane reached across to the first region's database —
// so "leadership moved to region B" meant a process in B holding a lock in A's database. Lose A and nothing
// survives. The canonical calls a region that can be failed over TO a state-bearing region and requires three
// things of it: a consensus member, a Postgres replica, and a warm control plane. The installer could render
// only two shapes, and neither was that.
func TestAJoiningRegionCanHoldState(t *testing.T) {
	dir := t.TempDir()
	if err := writeComposeFileFor(dir, machineShape{holds: regionShapeStateBearingJoin, edges: true}); err != nil {
		t.Fatalf("render: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	text := string(raw)
	has := func(service string) bool { return strings.Contains(text, "\n  "+service+":") }

	// It keeps state, and everything the operator's definition of a Control Plane contains.
	// ★ ONE MEMBER HERE, AND THE REPLICATION IS ACROSS MACHINES (2026-09-02). A second member beside the
	// first survives a process crash and not the machine; the member that matters is the one in the next
	// region, which the database door already names.
	for _, want := range []string{"dsse-postgres-a", "dsse-control-plane-a",
		"dsse-clickhouse", "dsse-archive", "dsse-console"} {
		if !has(want) {
			t.Fatalf("a state-bearing joining region must run %s — without it there is nothing here to promote, "+
				"or its history is written in another region", want)
		}
	}
	// ★ AND NOT A SECOND CONSENSUS STORE. One per deployment, a member per region; a second cluster would be a
	// second opinion about which database is primary.
	for _, unwanted := range []string{"dsse-store-a", "dsse-store-b", "dsse-store-c", "dsse-postgres-init"} {
		if has(unwanted) {
			t.Fatalf("a joining region must not run %s — the deployment already has one, and a second is a "+
				"second deployment wearing this one's name", unwanted)
		}
	}
	// ★ ITS PATRONI MEMBERS HAVE TO BE ABLE TO NAME A CONSENSUS STORE SOMEWHERE ELSE.
	if !strings.Contains(text, "DSSE_ETCD_HOSTS") {
		t.Fatal("the database members cannot be pointed at the deployment's consensus store, so they would " +
			"look for one on their own network and find nothing")
	}

	// ★★★ AND THE FILE IS VALID (2026-08-27, found by running it: "service dsse-control-plane-a depends on
	// undefined service dsse-postgres-init: invalid compose project"). The checks above ask which services are
	// present; none of them asks whether the file compose is handed can be read at all. A shape that renders
	// the right services and names one it does not define fails at the first command, and every assertion
	// about its contents passes.
	assertNoDanglingDependsOn(t, text)

	// And the shape reads back as itself: a repair must not reshape a region into something else.
	if got, known := regionShapeFromCompose(dir); !known || got.holds != regionShapeStateBearingJoin {
		t.Fatalf("the rendered region does not read back as a joining state-bearing one (got %v, known=%v)", got, known)
	}
}

// assertNoDanglingDependsOn fails if any service waits for one this file does not define.
// ★★★ BOTH LIST FORMS (2026-08-27). This read only the mapping form, "name: { condition: … }", and the
// generated file also uses "depends_on: [a, b, c]" — so a joining region's database waited for a consensus
// store in ANOTHER region, compose would have refused the whole project, and this guard passed. A check that
// knows one of two syntaxes is a check that is off half the time.
func assertNoDanglingDependsOn(t *testing.T, compose string) {
	t.Helper()
	svc := regexp.MustCompile(`^  ([a-z0-9-]+):`)
	mapped := regexp.MustCompile(`^\s+([a-z0-9-]+): \{ condition: `)
	listed := regexp.MustCompile(`^\s+depends_on: \[([a-z0-9, -]+)\]`)
	defined := map[string]bool{}
	for _, l := range strings.Split(compose, "\n") {
		if m := svc.FindStringSubmatch(l); m != nil {
			defined[m[1]] = true
		}
	}
	fail := func(name string) {
		t.Fatalf("a service waits for %q, which this file does not define — compose refuses the whole "+
			"project, and every check about its contents passes anyway", name)
	}
	for _, l := range strings.Split(compose, "\n") {
		if m := mapped.FindStringSubmatch(l); m != nil && !defined[m[1]] {
			fail(m[1])
		}
		if m := listed.FindStringSubmatch(l); m != nil {
			for _, name := range strings.Split(m[1], ",") {
				if name = strings.TrimSpace(name); name != "" && !defined[name] {
					fail(name)
				}
			}
		}
	}
}

// ★★★ AND ASKED OF EVERY SHAPE A MACHINE CAN BE. The dangling dependency lived in the shape that exists FOR a
// second region, which is the one nobody had rendered — so the guard was applied where it happened to be
// written rather than everywhere it applies.
func TestNoShapeWaitsForAServiceItDoesNotDefine(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "dsse.example", "Test Deployment", 10, false); err != nil {
		t.Fatalf("install: %v", err)
	}
	for _, m := range []struct {
		name  string
		shape machineShape
	}{
		{"the one-host reference", machineShape{holds: regionShapeStateBearing, edges: true}},
		{"a founding Control Plane machine", machineShape{holds: regionShapeStateBearing, edges: false}},
		{"a joining region that holds state", machineShape{holds: regionShapeStateBearingJoin, edges: true}},
		{"a joining region's Control Plane machine", machineShape{holds: regionShapeStateBearingJoin, edges: false}},
		{"a warm standby region", machineShape{holds: regionShapeStandbyCP, edges: true}},
		{"an Edges-only machine", machineShape{holds: regionShapeEdgesOnly, edges: true}},
	} {
		body, err := composeBodyFor(dir, m.shape)
		if err != nil {
			t.Fatalf("%s: %v", m.name, err)
		}
		t.Run(m.name, func(t *testing.T) { assertNoDanglingDependsOn(t, body) })
	}
}
