package main

import "strings"

// a_shape_cannot_fail_for_being_the_shape.go — telling "not redundant" apart from "broken".
//
// ★★★ THE SHAPE BEING PUBLISHED FAILED ITS OWN VERIFICATION (2026-09-03, measured by standing up one region
// on one machine from nothing — half of what the 2026-09-08 release publishes, and a shape nobody had walked).
//
// It came up correctly and -verify ended:
//
//	FAIL  more than one control-plane process is running
//	FAIL  the authority's durable state is redundant
//	FAIL  the region's doorway is not a single point
//	dsse-install -verify: 4 of 30 checks failed — this deployment is NOT ready to be handed over.
//
// Every one of those is true, and none of them is a fault. A deployment of ONE machine has one control plane,
// one copy of its state and one door; that is what the operator chose, and it is a shape this product ships.
// Reporting it as a failure teaches an operator that a red -verify is normal, which is the one thing this
// command must never teach.
//
// ★ THE SHAPE COMES FROM THE DEPLOYMENT'S OWN RECORD, not from what was passed on the command line. What is
// on the command line is what the operator chose to ask about; what is in deployment.env is what the
// installer built. A deployment with no control-plane peers, no database peers and one region in its map IS
// one machine, and it says so about itself.
func deploymentIsASingleMachine(dir string) bool {
	env := readDeploymentEnv(dir)
	if strings.TrimSpace(env["DSSE_CP_PEERS"]) != "" || strings.TrimSpace(env["DSSE_CP_DATA_PEERS"]) != "" {
		return false
	}
	if strings.TrimSpace(env["DSSE_PG_PEERS"]) != "" {
		return false
	}
	if strings.TrimSpace(env[edgeBackendsKey]) != "" {
		// The door balances over more than its own Edge, so there is another machine in this region.
		if len(strings.Split(env[edgeBackendsKey], ",")) > 1 {
			return false
		}
	}
	endpoints := strings.TrimSpace(env["DSSE_REGION_ENDPOINTS"])
	if endpoints == "" {
		// A deployment that names no region map has one region — the map exists to tell a device about the
		// others. See RegionEndpoints.
		return true
	}
	return len(strings.Split(endpoints, ";")) == 1
}

// singleMachineNote is what each redundancy question answers on a deployment that is one machine. It states
// the trade rather than passing silently: the operator chose a shape that cannot survive losing it, and a
// green line that did not say so would be its own kind of lie.
func singleMachineNote(what string) string {
	return "this deployment is ONE machine, so it has one " + what + " — that is the shape it was installed " +
		"in, not a fault. Losing that machine loses the deployment: nothing can be administered, no device " +
		"can enrol, and what the Edges hold is what they go on enforcing. The three-region shape is what " +
		"survives losing one"
}
