package main

import (
	"sort"
	"strings"
	"testing"
)

// ★ THE NAMES AND THE COMPOSE FILE ARE THE SAME LIST, OR THIS FAILS.
//
// edgeNodeNames and controlPlaneNodeNames are what the install order restarts, what the per-node admin doors
// are rendered for, and what -verify asks about. Every one of those is a lie the moment the compose file
// renders a different set — and each lie is quiet: the order fails at a step, the door gets a backend that
// resolves to nothing, and -verify reports a healthy deployment as broken.
func TestTheNamesAreTheServicesTheComposeFileDefines(t *testing.T) {
	body, err := composeBodyFor(t.TempDir(), foundingShape)
	if err != nil {
		t.Fatalf("render the compose file: %v", err)
	}
	var rendered []string
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimSpace(line), ":")
		if name == strings.TrimSpace(line) || strings.ContainsAny(name, " {}[]#") {
			continue // not a service key
		}
		// The region's own front door is called dsse-edge and terminates nothing; it is not an Edge.
		if name == "dsse-edge" || name == "dsse-control-plane" {
			continue
		}
		if strings.HasPrefix(name, "dsse-edge-") || strings.HasPrefix(name, "dsse-control-plane-") {
			rendered = append(rendered, name)
		}
	}
	want := append(composeServicesFor(edgeNodeNames), composeServicesFor(controlPlaneNodeNames)...)
	sort.Strings(rendered)
	sort.Strings(want)
	if strings.Join(rendered, " ") != strings.Join(want, " ") {
		t.Fatalf("the compose file defines %v, but the install order, the admin doors and -verify are all\n"+
			"built from %v — whichever is wrong, something is asked of a service that is not there, or a\n"+
			"service runs that nothing checks", rendered, want)
	}
}
