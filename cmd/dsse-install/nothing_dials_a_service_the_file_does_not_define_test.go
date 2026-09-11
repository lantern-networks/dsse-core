package main

import (
	"regexp"
	"strings"
	"testing"
)

// ★★★ NOTHING IN THE COMPOSE FILE DIALS A NAME THE COMPOSE FILE DOES NOT DEFINE (2026-09-02).
//
// Retiring the local haproxy that fronted a pair of Postgres members left dsse-postgres-init running
// `psql -h postgres` against a service that no longer exists. It has restart: on-failure, so it would not
// have failed loudly once — it would have retried forever, and a deployment whose role and database were
// never created is a deployment whose control plane cannot start.
//
// Compose itself catches only depends_on. A hostname inside a command, a URL or a DSN default is just a
// string, and on a container network a name that resolves to nothing is a connection refused at runtime — in
// a container that restarts, which reads as slowness rather than as a broken file.
func TestNothingDialsAServiceTheFileDoesNotDefine(t *testing.T) {
	for _, shape := range []struct {
		name  string
		shape machineShape
	}{
		{"a founding machine", foundingShape},
		{"a machine whose store spans regions", machineShape{holds: regionShapeStateBearing, edges: true, storeSpansRegions: true}},
		{"a joining region", machineShape{holds: regionShapeStateBearingJoin, edges: true}},
		{"edges behind the region's door", machineShape{holds: regionShapeEdgesOnly, edges: true, behindDoorway: true}},
	} {
		body, err := composeBodyFor(t.TempDir(), shape.shape)
		if err != nil {
			t.Fatalf("%s: render: %v", shape.name, err)
		}
		defined := composeServiceKeys(body)
		// The forms one service uses to name another: a psql/curl host flag, and the host of a URL or DSN.
		dials := regexp.MustCompile(`(?:-h |//|@)([a-z][a-z0-9]*(?:-[a-z0-9]+)+)(?::[0-9]+|[/ "]|$)`)
		for _, line := range strings.Split(body, "\n") {
			if t := strings.TrimSpace(line); strings.HasPrefix(t, "#") {
				continue
			}
			for _, m := range dials.FindAllStringSubmatch(line, -1) {
				host := m[1]
				// Only names this file is responsible for. Anything else is a real host, an image name or
				// a domain, and the deployment's own environment decides whether it resolves.
				if !strings.HasPrefix(host, "dsse-") {
					continue
				}
				if defined[host] {
					continue
				}
				t.Errorf("%s: dials %q, which this compose file does not define — on a container network that\n"+
					"is a connection refused at runtime, inside a container that restarts:\n  %s",
					shape.name, host, strings.TrimSpace(line))
			}
		}
	}
}
