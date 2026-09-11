package main

// plan_carry.go — packing ONE machine of a plan.
//
// ★★★ THE COMMAND LINE STOPS BEING WHERE THE ANSWERS LIVE. Packing a machine by flags meant repeating, for
// each one, its shape, its region and every address it is given — and every repetition was a place to be
// wrong silently. Here the plan says all of it and the machine is named.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// carryPlanMachine packs the named machine of a plan: its shape from what it holds, its region from where it
// is, and its per-machine values written into the deployment.env it carries.
func carryPlanMachine(plan *Plan, dir, dest, machineName string) error {
	if strings.TrimSpace(machineName) == "" {
		return fmt.Errorf("-machine is required with -plan and -carry. This plan describes %s",
			strings.Join(plan.MachineNames(), ", "))
	}
	region, machine, ok := plan.find(machineName)
	if !ok {
		return fmt.Errorf("this plan has no machine called %q; it describes %s",
			machineName, strings.Join(plan.MachineNames(), ", "))
	}
	values, err := plan.MachineEnvironment(machineName)
	if err != nil {
		return err
	}
	shape := plan.shapeOf(region, machine)
	// ★★★ THE DOORS ARE RENDERED FOR THE MACHINE RECEIVING THEM (2026-08-28, measured on a deployment built
	// from a plan). haproxy-edge.cfg and haproxy-postgres.cfg live in the minting directory, generated for the
	// region that minted it — so every machine of every other region was packed with region-a's doorway. It
	// routed region-a's plane names, named region-a's peers, and sent this region's own names to a backend
	// with no servers:
	//
	//	agents.region-b.dsse.lab -> region edge_fleet/<NOSRV>
	//
	// The name resolved, the certificate verified, and nothing served it. So the pack is taken from a copy
	// whose environment is this machine's, with the two doors written from THAT.
	staged, err := stageForMachine(dir, values)
	if err != nil {
		return err
	}
	defer os.RemoveAll(staged)
	carried, withheld, err := carryDeploymentFor(staged, dest, shape, region.ID, values)
	if err != nil {
		return err
	}
	reportCarry(dest, dir, carried, withheld)
	fmt.Printf("\n  ★ FROM THE PLAN, for %s of %s:\n", machine.Name, region.ID)
	for _, key := range []string{"DSSE_EDGE_REGION", "DSSE_REGION_BIND_A",
		"DSSE_REGION_ENDPOINTS", "DSSE_ETCD_HOSTS", "DSSE_PG_PEERS"} {
		if v := values[key]; v != "" {
			fmt.Printf("    %-24s %s\n", key, v)
		}
	}
	fmt.Printf("\n  Untar it on %s and start it. Nothing else on that machine has to be edited.\n", machine.Name)
	return nil
}

// MachineNames is every machine this plan describes, for a message that names what is available.
func (p *Plan) MachineNames() []string {
	out := []string{}
	for _, r := range p.Regions {
		for _, m := range r.Machines {
			out = append(out, m.Name)
		}
	}
	return out
}

// shapeOf turns what a machine HOLDS and what its region holds into the shape the rest of this installer
// already speaks. There is no second vocabulary: a plan produces the same machines the flags do.
// ★★★ AND THE TWO AXES ARE NOT ONE (2026-08-28, measured: the Edge machine came up running Postgres, etcd,
// ClickHouse and the archive, and no Edges at all). holds is what the REGION holds; edges is whether THIS
// MACHINE runs the Edge processes. Reading the region's holding onto every machine of it gives the state
// services to a machine whose job is to serve traffic — which is the co-location one component per machine
// exists to end, arrived at from the other direction.
func (p *Plan) shapeOf(region PlanRegion, machine PlanMachine) machineShape {
	// ★★★ WHAT THIS MACHINE RUNS IS WHAT IT SAYS IT RUNS (2026-08-31, found by standing up the first
	// three-region lab and reading the file it produced). holds became a list this afternoon so that one
	// machine could hold both components, and this function still answered the old question: a machine
	// holding the control plane was given edges:false, so a machine declaring BOTH rendered the control
	// plane, its stores, and its DOORWAY — with no Edge process behind it. A region with a door and no Edge
	// is the failure this deployment has a whole check for.
	edges := machine.Holds.has("edges")

	// ★★★ AND WHETHER THE STORE SPANS REGIONS IS THE PLAN'S TO KNOW, NOT A FLAG TO REMEMBER (same walk).
	// -store-spans-regions exists for a deployment installed without a plan. With one, asking the operator to
	// pass it as well is asking them to restate something the plan already says — and the printed order did
	// not pass it, so the founding machine rendered three members in one place while its environment named
	// one. The environment and the file it configures disagreed, and nothing said so.
	spans := len(p.stateBearingRegions()) > 1

	if !machine.Holds.has("control-plane") {
		// A machine that runs Edges runs Edges. What its region holds is the control-plane machine's business.
		//
		// ★★★ AND IT IS BEHIND THE REGION'S DOOR, NOT ONE OF THEM (2026-09-02). Until today this machine was
		// rendered with a doorway pair of its own, so "an Edge node behind the region's load balancer" did
		// not exist as a role: a region could only be widened by putting whole doorways beside each other,
		// each in front of its own Edge.
		return machineShape{holds: regionShapeEdgesOnly, edges: edges, behindDoorway: edges}
	}
	switch {
	case region.Founding:
		return machineShape{holds: regionShapeStateBearing, edges: edges, storeSpansRegions: spans}
	case region.HoldsState:
		return machineShape{holds: regionShapeStateBearingJoin, edges: edges, storeSpansRegions: spans}
	default:
		return machineShape{holds: regionShapeEdgesOnly, edges: edges}
	}
}

// stageForMachine copies the deployment into a temporary directory, writes the receiving machine's own
// values into its environment, and renders the two doors that are derived from them.
//
// A copy rather than the original, because the minting directory is a MACHINE — the founding control plane —
// and its doors are correct for it. Rendering another machine's over them would break the one that works.
func stageForMachine(dir string, values map[string]string) (string, error) {
	staged, err := os.MkdirTemp("", "dsse-plan-stage")
	if err != nil {
		return "", err
	}
	// Preserve the installer's modes: a restrictive caller umask must not make
	// public CA certificates or database initialization files unreadable in containers.
	if out, cerr := exec.Command("cp", "-pR", dir+string(filepath.Separator)+".", staged).CombinedOutput(); cerr != nil {
		os.RemoveAll(staged)
		return "", fmt.Errorf("stage %s: %v: %s", dir, cerr, out)
	}
	envPath := filepath.Join(staged, "deployment.env")
	body, rerr := os.ReadFile(envPath)
	if rerr != nil {
		os.RemoveAll(staged)
		return "", rerr
	}
	if werr := os.WriteFile(envPath, []byte(PlanEnvironmentFor(string(body), values)), 0o600); werr != nil {
		os.RemoveAll(staged)
		return "", werr
	}
	// ★★★ EVERY DOOR THIS INSTALLER GENERATES, NOT A LIST THAT DRIFTED (2026-08-31, measured on the first
	// three-region deployment). haproxy.cfg — the CONTROL PLANE's own door, which is what an Edge pulls its
	// configuration through — was missing here, so every joining region ran the FOUNDING machine's copy of
	// it. That was invisible for as long as the two were identical, and became a region whose Edge could not
	// reach the leader the moment the doors differed by a peer list.
	//
	// ★ THE FILES A WRITER OWNS ARE THE FILES IT REWRITES. Adding a door and forgetting this line is the same
	// defect again, so the three names live beside the three calls below and nowhere else.
	for _, f := range []string{"haproxy.cfg", "haproxy-edge.cfg", "haproxy-postgres.cfg"} {
		if err := os.Remove(filepath.Join(staged, f)); err != nil && !os.IsNotExist(err) {
			os.RemoveAll(staged)
			return "", err
		}
	}
	if err := writeFrontDoorConfig(staged); err != nil {
		os.RemoveAll(staged)
		return "", err
	}
	if err := writeRegionFrontDoorConfig(staged, planeNamesFor(planeHostOf(staged))); err != nil {
		os.RemoveAll(staged)
		return "", err
	}
	if err := writeDatabaseFrontDoorConfig(staged); err != nil {
		os.RemoveAll(staged)
		return "", err
	}
	return staged, nil
}
