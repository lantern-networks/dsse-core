package main

// plan_install.go — installing the founding region from the description.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// applyPlanToFoundingMachine writes the founding region's own machine values into the deployment it just
// minted, and regenerates the doors that depend on them.
//
// ★★★ THE MINTING DIRECTORY IS A MACHINE TOO, and that is the one nobody thinks of. Every other machine gets
// its values when it is packed; this one is where the deployment was created, so it kept whatever the
// defaults were — its doorway on a lab port, its consensus store on loopback, its database members named the
// same as every other region's. A deployment whose FIRST region is the one misconfigured is the shape where
// nothing else can join it.
func applyPlanToFoundingMachine(plan *Plan, dir string) error {
	founding := plan.foundingRegion()
	machine := founding.controlPlane()
	if machine.Name == "" {
		return fmt.Errorf("the plan's founding region has no control-plane machine")
	}
	return applyPlanTo(plan, dir, founding, machine)
}

// applyPlanToThisMachine makes an EXISTING deployment directory be the named machine of the plan: its own
// values, its own shape, its own doors. What a carry does for a machine that is about to receive one, for the
// machine that is already there.
func applyPlanToThisMachine(plan *Plan, dir, machineName string) error {
	region, machine, ok := plan.find(machineName)
	if !ok {
		return fmt.Errorf("this plan has no machine called %q; it describes %s",
			machineName, strings.Join(plan.MachineNames(), ", "))
	}
	return applyPlanTo(plan, dir, region, machine)
}

func applyPlanTo(plan *Plan, dir string, founding PlanRegion, machine PlanMachine) error {
	values, err := plan.MachineEnvironment(machine.Name)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "deployment.env")
	body, rerr := os.ReadFile(path)
	if rerr != nil {
		return rerr
	}
	if werr := os.WriteFile(path, []byte(PlanEnvironmentFor(string(body), values)), 0o600); werr != nil {
		return werr
	}
	// ★ AND THIS MACHINE'S MEMBER MATERIAL, if the deployment's store spans regions. Nothing writes it at
	// minting time because minting does not know which region this machine is.
	if cert, key, serr := storeMemberMaterialFor(dir, values, time.Now().UTC(), storeMemberYears); serr != nil {
		return serr
	} else if cert != nil {
		if werr := os.WriteFile(filepath.Join(dir, storeMemberFile), cert, 0o644); werr != nil {
			return werr
		}
		if werr := os.WriteFile(filepath.Join(dir, storeMemberKeyFile), key, 0o600); werr != nil {
			return werr
		}
	}
	// ★★★ AND WHAT THIS MACHINE RUNS (2026-08-28, measured by shipping the minted directory to the machine the
	// plan says it is). The founding install renders the shape it has always rendered — a region that holds
	// state AND runs Edges — because until now nothing told it otherwise. The plan does: it says cp-a holds
	// the control plane and edge-a holds the Edges. Shipped unchanged, the control-plane machine came up
	// running sixteen containers including an Edge fleet, which is the co-location every other part of this
	// arrangement exists to end.
	//
	// ★ THE REWRITE VARIANT, deliberately: writeComposeFileFor leaves a file that is already there alone, and
	// the founding install has just written one. Calling it here was a no-op that read like a fix.
	if err := rewriteComposeFileFor(dir, plan.shapeOf(founding, machine)); err != nil {
		return err
	}
	if err := writeLaunchScripts(dir); err != nil {
		return err
	}
	// ★ AND THE DOORS, WHICH READ THOSE VALUES. The region doorway names the other regions' planes and the
	// database door names their members; both were written before the values existed, and a file that is
	// already there is deliberately left alone by the writers — so they are removed and written again.
	for _, f := range []string{"haproxy-edge.cfg", "haproxy-postgres.cfg"} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor(planeHostOf(dir))); err != nil {
		return err
	}
	if err := writeDatabaseFrontDoorConfig(dir); err != nil {
		return err
	}
	fmt.Printf("\n★ FROM THE PLAN — this deployment is %q, and it has %d region(s):\n",
		plan.Deployment, len(plan.Regions))
	for _, r := range plan.Regions {
		mark := "joins"
		if r.Founding {
			mark = "founds"
		}
		names := []string{}
		for _, m := range r.Machines {
			names = append(names, m.Name+" ("+m.Holds.String()+")")
		}
		fmt.Printf("    %-10s %-7s %s\n", r.ID, mark, strings.Join(names, ", "))
	}
	fmt.Printf("\n  This directory IS %s of %s. Pack every other machine from it:\n", machine.Name, founding.ID)
	for _, m := range plan.MachineNames() {
		if m == machine.Name {
			continue
		}
		fmt.Printf("    dsse-install -plan <plan> -dir %s -carry %s.tar.gz -machine %s\n", dir, m, m)
	}
	fmt.Printf("\n  ★ Nothing on any of them has to be edited afterwards. What differs between machines is in\n")
	fmt.Printf("  the plan, and what does not is the deployment's.\n")
	return nil
}
