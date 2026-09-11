package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ★★★ THERE ARE THREE SHAPES AND A TWO-WAY GUESS SILENTLY RESHAPED A REGION (2026-08-25, caught by diffing a
// rewrite before anything was restarted). Regenerating a joining region's compose from "state-bearing or
// edges-only" replaced its warm control plane with an edges-only file: on the next restart that region would
// have come back without the control plane it had, for no reason anybody asked for.
func TestTheShapeIsReadFromWhatTheFileStandsUp(t *testing.T) {
	cases := []struct {
		name     string
		services []string
		want     machineShape
		known    bool
	}{
		{"state-bearing, the whole store on this host",
			[]string{"dsse-store-a", "dsse-store-b", "dsse-store-c", "dsse-postgres-a", "dsse-control-plane-a", "dsse-edge-a", "dsse-edge"},
			machineShape{holds: regionShapeStateBearing, edges: true}, true},
		// ★★★ THE SAME REGION KIND WITH ONE STORE MEMBER IS A DIFFERENT FILE (2026-09-02, measured on a live
		// three-region deployment). Every machine of a three-regions-of-one-machine deployment has store-a,
		// postgres-a and control-plane-a, and the repair read that as "the founding host" and added
		// dsse-store-b and dsse-store-c to a machine that holds one vote. The file says which it is.
		{"state-bearing, one member of a store that spans regions",
			[]string{"dsse-store-a", "dsse-postgres-a", "dsse-control-plane-a", "dsse-edge-a", "dsse-edge"},
			machineShape{holds: regionShapeStateBearing, edges: true, storeSpansRegions: true}, true},
		{"a warm control plane joining the deployment's database", []string{"dsse-control-plane-a", "dsse-edge-a", "dsse-edge"}, machineShape{holds: regionShapeStandbyCP, edges: true}, true},
		{"edges only", []string{"dsse-edge-a", "dsse-edge"}, machineShape{holds: regionShapeEdgesOnly, edges: true}, true},
		// ★ AN EDGE MACHINE BEHIND THE REGION'S DOOR RENDERS NO DOOR. It has Edges and no doorway, and a
		// repair that assumed every Edge machine is a doorway would put a second door in the region.
		{"edges behind the region's door", []string{"dsse-edge-a"},
			machineShape{holds: regionShapeEdgesOnly, edges: true, behindDoorway: true}, true},
		// ★★★ AND A CONTROL-PLANE MACHINE, WHICH IS THE SAME REGION WITH NO EDGES IN THIS FILE. Reading only
		// the region kind and assuming Edges is how a repair puts a fleet back beside the authority.
		{"a control-plane machine of a state-bearing region",
			[]string{"dsse-store-a", "dsse-store-b", "dsse-store-c", "dsse-postgres-a", "dsse-control-plane-a"},
			machineShape{holds: regionShapeStateBearing, edges: false}, true},
		{"a control-plane machine of a JOINING region",
			[]string{"dsse-postgres-a", "dsse-control-plane-a"},
			machineShape{holds: regionShapeStateBearingJoin, edges: false}, true},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		body := "services:\n"
		for _, s := range tc.services {
			body += "  " + s + ":\n    image: dsse\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		got, known := regionShapeFromCompose(dir)
		if got != tc.want || !known {
			t.Fatalf("%s: shape=%v known=%v; want %v/true", tc.name, got, known, tc.want)
		}
	}

	// ★ AND A FILE THIS INSTALLER DOES NOT RECOGNISE IS LEFT ALONE. "I cannot tell" must not resolve to a
	// shape — that is the guess this test exists to prevent, one level up.
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, "docker-compose.yml"), []byte("services:\n  something-else:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, known := regionShapeFromCompose(empty); known {
		t.Fatalf("an unrecognised compose file was given a shape")
	}
	if _, known := regionShapeFromCompose(t.TempDir()); known {
		t.Fatalf("a directory with no compose file was given a shape")
	}
}
