package main

import (
	"regexp"
	"strings"
	"testing"
)

// ★★★ A REGION HAS ONE DESTINATION AND IT IS THE DOOR (2026-09-02, the operator: "for both connectors and
// agents the destination IP is one per region, and that is the haproxy").
//
// Measured on the live lab, a machine carrying its region's door was also listening on 0.0.0.0:8443,
// 0.0.0.0:19443 and 0.0.0.0:19543 — the Edge's agent plane, the Edge's admin plane and the control plane's
// admin plane, each a way in beside the door. That is not a smaller door. The door is what carries a device's
// own address through in the PROXY header, and a node believes that header only from the addresses it was
// told to trust; a connection arriving on 8443 directly can claim to come from anywhere.
//
// Every one of them was published for a reason that had stopped being true, and none of them was noticed by
// anything: compose is happy, every screen says healthy, and the extra listeners appear only if somebody
// thinks to ask the machine what it is listening on.
//
// So: every port this file publishes defaults to LOOPBACK — reaching exactly the machine already running it —
// except the two that are meant to be reachable, which are named here.
func TestEveryPublishedPortIsLoopbackExceptTheDoor(t *testing.T) {
	// The region's own front door: the one destination. And an Edge on a machine that has NO door — the door
	// that fronts it is on another host and has to reach it.
	reachable := map[string]string{
		"${DSSE_REGION_BIND_A:-}${DSSE_REGION_PORT:-18443}:443": "the region's front door",
		"${DSSE_EDGE_AGENT_PORT:-8443}:8443":                    "an Edge behind a door on another machine",
		"${DSSE_EDGE_ADMIN_PORT:-19443}:9443":                   "an Edge behind a door on another machine",
		// ★ A WARM CONTROL PLANE IN A REGION THAT HOLDS NO STATE. It renders no front door for the
		// authority's names, and when leadership moves there every other region has to be able to write to
		// it. Measured as an outbox that grew and delivered nothing. Deliberate, and the reason is beside
		// the ports in compose.go — not a shape reshaped today, and not changed on a guess.
		"${DSSE_CP_A_ADMIN_PORT:-19543}:9443": "a warm control plane with no front door of its own",
		"${DSSE_CP_A_DATA_PORT:-19545}:8443":  "a warm control plane with no front door of its own",
	}
	publish := regexp.MustCompile(`"([^"]+:[0-9]+)"`)
	for _, tc := range []struct {
		name  string
		shape machineShape
	}{
		{"a founding machine", foundingShape},
		{"a machine whose store spans regions", machineShape{holds: regionShapeStateBearing, edges: true, storeSpansRegions: true}},
		{"a joining region", machineShape{holds: regionShapeStateBearingJoin, edges: true, storeSpansRegions: true}},
		{"a warm control plane", machineShape{holds: regionShapeStandbyCP, edges: true}},
		{"a control-plane machine with no Edges", machineShape{holds: regionShapeStateBearing, edges: false, storeSpansRegions: true}},
		{"edges behind the region's door", machineShape{holds: regionShapeEdgesOnly, edges: true, behindDoorway: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := composeBodyFor(t.TempDir(), tc.shape)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			inPorts := false
			for _, line := range strings.Split(body, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") {
					continue
				}
				if strings.HasPrefix(trimmed, "ports:") {
					inPorts = !strings.Contains(trimmed, "[") // a list on the next lines
					for _, m := range publish.FindAllStringSubmatch(trimmed, -1) {
						checkPublished(t, tc.name, m[1], reachable)
					}
					continue
				}
				if !inPorts {
					continue
				}
				if !strings.HasPrefix(trimmed, "- ") {
					inPorts = false
					continue
				}
				for _, m := range publish.FindAllStringSubmatch(trimmed, -1) {
					checkPublished(t, tc.name, m[1], reachable)
				}
			}
		})
	}
}

func checkPublished(t *testing.T, shape, spec string, reachable map[string]string) {
	t.Helper()
	if _, ok := reachable[spec]; ok {
		return
	}
	// Everything else must default to an address that reaches only this machine.
	if strings.Contains(spec, "127.0.0.1") {
		return
	}
	t.Errorf("%s publishes %q, which defaults to every interface. A region has ONE destination and it is the\n"+
		"door: a port beside it is a way in that carries no device address in a PROXY header. Bind it to\n"+
		"127.0.0.1, or add it to the list in this test with the reason it is meant to be reachable.", shape, spec)
}
