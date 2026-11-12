package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The door opens one connection to an Edge for every connection a device holds, all from one address to one
// address, so each takes a local port. With the kernel's default range (about 28,000) a fleet of 10,006 devices
// returning within thirty seconds was refused for half a minute: "Connect() failed for backend edge_fleet: no
// free ports" (measured 2026-11-11). Every rendering that carries the door must give it the whole range.
func TestTheDoorIsGivenEveryLocalPort(t *testing.T) {
	doors := 0
	for _, tc := range []struct {
		name  string
		shape machineShape
	}{
		{"a founding machine", foundingShape},
		{"a machine whose store spans regions", machineShape{holds: regionShapeStateBearing, edges: true, storeSpansRegions: true}},
		{"a joining region", machineShape{holds: regionShapeStateBearingJoin, edges: true, storeSpansRegions: true}},
		{"a warm control plane", machineShape{holds: regionShapeStandbyCP, edges: true}},
		{"a control-plane machine with no Edges", machineShape{holds: regionShapeStateBearing, edges: false, storeSpansRegions: true}},
		{"edges only", machineShape{holds: regionShapeEdgesOnly, edges: true}},
		{"edges behind the region's door", machineShape{holds: regionShapeEdgesOnly, edges: true, behindDoorway: true}},
	} {
		dir := t.TempDir()
		if err := writeComposeFileFor(dir, tc.shape); err != nil {
			t.Fatalf("%s: render the compose file: %v", tc.name, err)
		}
		files, _ := filepath.Glob(filepath.Join(dir, "*.y*ml"))
		if len(files) == 0 {
			t.Fatalf("%s: no compose file was rendered", tc.name)
		}
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			// The door is the service that mounts the Edge-facing proxy configuration.
			n := strings.Count(text, `"./haproxy-edge.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro"`)
			if n == 0 {
				continue
			}
			doors += n
			if got := strings.Count(text, `net.ipv4.ip_local_port_range: "1024 65535"`); got != n {
				t.Errorf("%s: %d door(s) in %s but %d carry the local port range", tc.name, n, filepath.Base(f), got)
			}
		}
	}
	if doors == 0 {
		t.Fatal("no rendering carried a door, so this test checked nothing")
	}
}
