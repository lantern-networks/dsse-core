package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// an_edge_can_be_added_to_a_running_region.go — growing a region's Edge fleet after the deployment is up.
//
// ★★★ THE INSTALLER COULD BUILD A REGION OF TWO EDGES AND COULD NOT GROW ONE (2026-09-03, the operator's
// requirement: "an Edge should be in a form that can be added later", and "one door, load-balanced behind it").
//
// Everything for the second Edge already existed. A machine may hold only "edges"; -carry packs it; the
// printed order names it; DSSE_EDGE_BACKENDS is the list the region's door balances over, and edgeFleetServers
// renders one `server` line per entry. What was missing is the only step that is not on the new machine:
//
//	the door of a region that is ALREADY RUNNING has DSSE_EDGE_BACKENDS from the plan it was installed with,
//	and nothing re-derives it when the plan grows.
//
// So the new Edge would come up, admit nobody, and appear in no backend — healthy, reachable from its own
// machine, and absent from the one address devices use. -verify would even pass, because it asks each Edge
// directly at its own address rather than through the door.
//
// ★ IT IS ADDITIVE AND IT KEEPS THE PREVIOUS FILE. Same discipline as a repair: regenerate, keep what was
// there beside it, and report per file what actually changed — because an operator running this on a live
// region needs to know whether anything moved before they reload the door.
//
// ★★ AND IT DOES NOT RESTART THE REGION. haproxy is reloaded, not recreated: `docker compose up -d` on the
// door alone replaces the container and drops every established connection in the region, which for a change
// whose entire purpose is capacity would be an outage caused by growth.
func addAnEdgeToARunningRegion(dir, planPath, machineName string) error {
	plan, err := LoadPlan(planPath)
	if err != nil {
		return err
	}
	region, machine, ok := plan.find(machineName)
	if !ok {
		return fmt.Errorf("this plan has no machine called %q, so there is nothing to add. The machine must "+
			"be IN the plan first: that is what makes its address derivable rather than typed here", machineName)
	}
	if !machine.Holds.has("edges") {
		return fmt.Errorf("%q holds %s, not edges — this teaches a region's door about a machine that runs "+
			"Edges behind it", machineName, strings.Join(machine.Holds, "+"))
	}
	if machine.Holds.has("control-plane") {
		return fmt.Errorf("%q holds the control plane, so it holds its region's door rather than sitting "+
			"behind one. A machine added for capacity holds only edges", machineName)
	}
	if len(machine.Addresses) == 0 {
		return fmt.Errorf("%q has no address in the plan, so the door would have nothing to send to", machineName)
	}
	// ★ THIS MUST BE THE DOOR OF THAT REGION. Run on the wrong machine it would write a backend list naming
	// Edges that machine cannot reach, and the region it IS the door of would lose its own list.
	env := readDeploymentEnv(dir)
	if here := strings.TrimSpace(env["DSSE_EDGE_REGION"]); !strings.EqualFold(here, region.ID) {
		return fmt.Errorf("this directory is region %q and %q is being added to region %q: run this on the "+
			"machine that holds %s's door", here, machineName, region.ID, region.ID)
	}

	// The list the door balances over: this machine's own Edge first, then every machine of the region that
	// holds edges and not the control plane. Derived from the plan, so running it twice says "no change".
	behind := []string{}
	for _, other := range region.Machines {
		if other.Holds.has("control-plane") || !other.Holds.has("edges") || len(other.Addresses) == 0 {
			continue
		}
		behind = append(behind, fmt.Sprintf("%s:%d", strings.TrimSpace(other.Addresses[0]), planEdgeBehindDoorAgentPort))
	}
	sort.Strings(behind)
	want := strings.Join(append([]string{"dsse-edge-a:8443"}, behind...), ",")
	had := strings.TrimSpace(env[edgeBackendsKey])
	// ★★★ "ALREADY BALANCES OVER THESE" IS NOT "NOTHING TO DO" (2026-09-03, caught the first time this was run
	// twice). This returned here when the door's backend list matched, and skipped the sibling list and the
	// compose file with it — so a second run of the very command that was supposed to complete the job did
	// nothing and said so cheerfully. Each thing this writes is checked on its own.
	if had != want {
		if err := setDeploymentEnvValue(dir, edgeBackendsKey, want); err != nil {
			return err
		}
	}
	// ★★★ AND THE EDGES OF A REGION HOLD A LINK TO EACH OTHER (2026-09-03, found by walking this). The first
	// version of this wrote only the door's backend list, so the machine already running learned it had a new
	// Edge to balance over and NOT that it had a sibling to relay through. The link is directional — a peer
	// registry holds only the sessions this node DIALLED — so a one-sided list leaves half the flows with no
	// path: the ones arriving here for a connector whose tunnel the new machine holds.
	siblings := []string{}
	for _, other := range region.Machines {
		if other.Name == thisMachineName(dir, region) || !other.Holds.has("edges") || len(other.Addresses) == 0 {
			continue
		}
		siblings = append(siblings, siblingEdgeURL(other))
	}
	sort.Strings(siblings)
	wantSiblings := strings.Join(siblings, ",")
	siblingsChanged := strings.TrimSpace(env["DSSE_EDGE_SIBLINGS"]) != wantSiblings
	if siblingsChanged {
		if err := setDeploymentEnvValue(dir, "DSSE_EDGE_SIBLINGS", wantSiblings); err != nil {
			return err
		}
	}
	regeneratingDerivedFiles = true
	defer func() { regeneratingDerivedFiles = false }()
	// ★★★ AND THE COMPOSE FILE, BECAUSE THIS MACHINE'S EDGE NOW HAS TO BE REACHABLE (2026-09-03, caught by
	// reading what this tool printed against what it did). It told the operator to recreate the Edge because
	// it "now publishes its peer port" — and rewrote nothing that would make it. A tool whose printed sentence
	// is not true of the file it just wrote is the failure this whole session keeps finding.
	//
	// The shape is READ from the compose file that is already here, never assumed: the same discipline the
	// repair path uses, for the same reason — reshaping a deployment nobody asked to reshape is how a
	// maintenance step becomes an outage.
	composeChanged := false
	if shape, known := regionShapeFromCompose(dir); known {
		before, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
		if err := rewriteComposeFileFor(dir, shape); err != nil {
			return fmt.Errorf("rewrite this machine's compose file: %w", err)
		}
		after, _ := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
		composeChanged = string(before) != string(after)
	}
	planeHost := strings.TrimSpace(env["DSSE_AGENT_PLANE_NAME"])
	if planeHost == "" {
		planeHost = strings.TrimSpace(env["EDGE_HOST"])
	}
	if err := writeRegionFrontDoorConfig(dir, planeNamesFor(planeHost)); err != nil {
		return fmt.Errorf("re-render %s's front door: %w", region.ID, err)
	}
	// ★★★ "NOTHING CHANGED" IS NOT "NOTHING LEFT TO DO" (2026-09-03, met while adding a fifth machine). This
	// returned here with one line and no steps — but what this command writes is only the part that happens on
	// THIS machine. The new machine still has to be given a certificate name, packed, and started, and an
	// operator who ran this twice was told none of that the second time. The steps are printed either way; only
	// the first line differs.
	unchanged := had == want && !siblingsChanged && !composeChanged
	if unchanged {
		fmt.Printf("dsse-install: %s is already set up for %s — this machine has nothing left to write.\n",
			region.ID, machineName)
	} else {
		fmt.Printf("dsse-install: %s's door now balances over %d Edge(s):\n", region.ID, len(behind)+1)
	}
	if !unchanged {
		fmt.Printf("  siblings this machine will relay through: %s\n", wantSiblings)
		fmt.Printf("  was %s\n  now %s\n", had, want)
	}
	// ★★★ THE COMMAND THIS USED TO PRINT DID NOT RUN (2026-09-03, measured on the first live use — the same
	// hour this file was written). It named `-p dsse-<region>` and a service called `dsse-front-door`, and the
	// machine answered "No container to kill": the founding region's compose project is `dsse`, and the door's
	// service is `dsse-edge` — `dsse-edge-a` is the Edge itself. Two guesses, both wrong, in a tool whose whole
	// value is that an operator can follow what it prints.
	//
	// So it prints no names it cannot know. The door is the container mounting this region's door config, and
	// docker can be asked which one that is.
	// ★★★ IN THE ORDER THAT WORKS, WHICH IS NOT THE ORDER THIS FIRST PRINTED (2026-09-03, learned by walking
	// it). -add-host was printed AFTER the carry, so following it literally packs a leaf that does not carry
	// the new machine's name, the sibling link fails to verify, and the machine has to be carried a second
	// time. The certificate has to be widened BEFORE anything is packed from it.
	fmt.Printf("\nIn this order:\n\n")
	step := 0
	next := func(what string, cmds ...string) {
		step++
		fmt.Printf("%d. %s\n", step, what)
		for _, c := range cmds {
			fmt.Printf("     %s\n", c)
		}
		fmt.Printf("\n")
	}
	if name := strings.TrimSpace(machine.Reachable); name != "" {
		// ★★★ AND ON THE MACHINE THAT CAN DO IT (2026-09-03, met by following this on the machine it was
		// printed on: "read /opt/dsse/osaka/root.key: no such file"). Issuing a certificate needs the
		// authority, and -carry leaves authority/ behind on purpose — so every machine except the one the
		// deployment was minted on holds the leaves and cannot re-issue them. Printing this step here, with
		// no note of where it runs, sends an operator to a machine that will refuse it.
		next("Widen this deployment's certificates FIRST, ON THE MACHINE IT WAS MINTED ON — a sibling Edge is\n"+
			"   dialled by name, and a leaf packed before this does not carry it. Only that machine holds the\n"+
			"   authority; every other one was carried and cannot re-issue:",
			fmt.Sprintf("dsse-install -add-host %s -dir <that machine's deployment directory>", name))
	}
	next("Pack the new machine, here, then move the file to it:",
		fmt.Sprintf("dsse-install -plan <plan> -dir %s -carry %s.tar.gz -machine %s", dir, machineName, machineName))
	next(fmt.Sprintf("On %s — it needs the product image too: the archive carries configuration and\n"+
		"   material, NOT the image this region already runs.", machineName),
		fmt.Sprintf("tar xzf %s.tar.gz -C /opt/dsse/%s", machineName, region.ID),
		"docker compose --env-file deployment.env up -d")
	if !unchanged {
		next("Reload this region's door. This replaces no container and drops no established connection:",
			"sudo docker kill -s HUP $(sudo docker ps --filter label=com.docker.compose.service=dsse-edge --format '{{.Names}}')")
	}
	if composeChanged {
		next("And recreate THIS machine's Edge once — its compose changed, because it now publishes the\n"+
			"   port a sibling dials. One container, not the region:",
			"docker compose --env-file deployment.env up -d dsse-edge-a")
	} else {
		next("And restart this machine's Edge so it picks up the new sibling:",
			"docker compose --env-file deployment.env up -d dsse-edge-a")
	}
	return nil
}

// setDeploymentEnvValue writes one key into deployment.env, replacing it in place when it is already there so
// the file keeps its order and its comments. The previous file is kept beside it.
func setDeploymentEnvValue(dir, key, value string) error {
	path := filepath.Join(dir, "deployment.env")
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := os.WriteFile(path+".before-add-edge", body, 0o600); err != nil {
		return fmt.Errorf("keep the previous %s: %w", path, err)
	}
	lines := strings.Split(string(body), "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key+"=") {
			lines[i] = fmt.Sprintf("%s='%s'", key, value)
			replaced = true
			break
		}
	}
	if !replaced {
		lines = append(lines, fmt.Sprintf("%s='%s'", key, value))
	}
	return os.WriteFile(path, []byte(withTrailingNewline(strings.Join(lines, "\n"))), 0o600)
}

// thisMachineName answers which machine of the region this directory belongs to, so the sibling list can leave
// it out. The compose file names the region's services identically on every machine, so the answer comes from
// the door's own backend list: the entry that is a compose service name rather than an address is this host's
// Edge, and every other entry is somebody else's.
func thisMachineName(dir string, region PlanRegion) string {
	env := readDeploymentEnv(dir)
	mine := map[string]bool{}
	for _, e := range strings.Split(env[edgeBackendsKey], ",") {
		host := strings.TrimSpace(e)
		if i := strings.IndexByte(host, ':'); i >= 0 {
			host = host[:i]
		}
		if host != "" {
			mine[host] = true
		}
	}
	// A machine whose address is NOT in this door's backend list is not this one. The doorway machine's own
	// Edge appears as a compose service name, so its address is absent — which is exactly what identifies it.
	for _, m := range region.Machines {
		if len(m.Addresses) == 0 {
			continue
		}
		if !mine[strings.TrimSpace(m.Addresses[0])] && m.Holds.has("control-plane") {
			return m.Name
		}
	}
	return ""
}
