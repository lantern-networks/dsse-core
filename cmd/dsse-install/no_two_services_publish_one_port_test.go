package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// composeTemplateForTest renders the full state-bearing compose — the shape that carries every service.
func composeTemplateForTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := writeComposeFileFor(dir, machineShape{holds: regionShapeStateBearing, edges: true}); err != nil {
		t.Fatalf("render compose: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read compose: %v", err)
	}
	return string(raw)
}

// ★★★ A SERVICE THAT INHERITS A PUBLISHED PORT IS A COLLISION, NOT A SERVICE (2026-08-27, introduced and
// caught within a minute of each other while making the consensus store reachable from another region).
//
// Publishing a port on the anchor `dsse-store-a: &dsse-store` gave it to `dsse-store-b` and `dsse-store-c`
// through their `<<: *dsse-store` merge as well, so three containers would have bound the same host port and
// two of them would never start. Nothing in the file looks wrong: the two services do not mention ports at all.
//
// ★ WHICH IS WHY A TEXT SCAN FOR DUPLICATE `ports:` LINES WOULD HAVE MISSED IT. The check has to know that a
// merge carries the key, so it reads the anchors first and then asks whether each merging service says
// something of its own.
func TestNoServiceInheritsAPublishedPort(t *testing.T) {
	compose := composeTemplateForTest(t)

	// Anchors that themselves publish a port: `name: &anchor` … `ports:` before the next service.
	anchorDecl := regexp.MustCompile(`^  ([a-z0-9-]+): &([a-z0-9-]+)\s*$`)
	serviceDecl := regexp.MustCompile(`^  ([a-z0-9-]+):\s*$`)
	mergeDecl := regexp.MustCompile(`^\s+<<: \*([a-z0-9-]+)\s*$`)

	publishing := map[string]bool{} // anchor name -> publishes a port
	var currentAnchor, currentService string
	lines := strings.Split(compose, "\n")
	for _, l := range lines {
		if m := anchorDecl.FindStringSubmatch(l); m != nil {
			currentService, currentAnchor = m[1], m[2]
			continue
		}
		if m := serviceDecl.FindStringSubmatch(l); m != nil {
			currentService, currentAnchor = m[1], ""
			continue
		}
		if currentAnchor != "" && strings.HasPrefix(strings.TrimSpace(l), "ports:") {
			publishing[currentAnchor] = true
		}
	}
	_ = currentService

	// Now: any service merging a publishing anchor must declare ports of its own.
	currentService = ""
	merged := ""
	declares := map[string]bool{}
	// ★ EVERY ANCHOR A SERVICE MERGES, NOT THE LAST ONE. The first version of this check kept a single anchor
	// per service and was overwritten by the nested `<<: *dsse-store-env` inside `environment:` — so it read
	// the store members as merging something that publishes nothing, and passed on the very bug it was written
	// for. Proven by breaking the file and watching it stay green.
	mergesFrom := map[string][]string{}
	for _, l := range lines {
		if m := anchorDecl.FindStringSubmatch(l); m != nil {
			currentService, merged = m[1], ""
			continue
		}
		if m := serviceDecl.FindStringSubmatch(l); m != nil {
			currentService, merged = m[1], ""
			continue
		}
		if m := mergeDecl.FindStringSubmatch(l); m != nil && currentService != "" {
			merged = m[1]
			mergesFrom[currentService] = append(mergesFrom[currentService], merged)
			continue
		}
		if currentService != "" && strings.HasPrefix(strings.TrimSpace(l), "ports:") {
			declares[currentService] = true
		}
	}
	for svc, anchors := range mergesFrom {
		for _, anchor := range anchors {
			if publishing[anchor] && !declares[svc] {
				t.Fatalf("%q merges %q, which publishes a host port, and declares none of its own — it would "+
					"bind the port another service already holds and never start", svc, anchor)
			}
		}
	}
}
