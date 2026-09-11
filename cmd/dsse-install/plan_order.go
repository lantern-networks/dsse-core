package main

// plan_order.go — the order, derived from the description.
//
// ★★★ THE ORDER WAS NOWHERE, AND IT IS HALF THE INSTALL (2026-08-28). A deployment's machines cannot be
// brought up in any sequence: a region that JOINS needs the founding region's consensus store already
// answering, an Edge needs the control plane of its own region, and the administrator must be created while
// the break-glass credential is still armed and the credential closed afterwards — before any other machine
// is packed, or every machine created from then on is born answering 401.
//
// All of that was learned by doing it wrong. None of it was written down, so the next person learns it the
// same way. It is derived here, from the same description everything else comes from, and each step says what
// must already be true — so a step taken too early fails with a sentence about the deployment rather than
// with whatever the component says when its dependency is missing.

import (
	"fmt"
	"strings"
)

// PlanStep is one thing a person does, where they do it, and what must already be true.
type PlanStep struct {
	// Machine is where this runs. The minting machine for everything that packs; the receiving machine for
	// everything that starts.
	Machine string
	// Do is the command, exactly.
	Do string
	// Needs is the state this step depends on, in words a person can check.
	Needs string
	// Why is what goes wrong if it is done out of order.
	Why string
}

// InstallOrder is every step of standing this deployment up, in the only order that works.
func (p *Plan) InstallOrder(dir, planPath string) []PlanStep {
	founding := p.foundingRegion()
	minting := founding.controlPlane()
	steps := []PlanStep{
		{
			Machine: minting.Name,
			Do:      fmt.Sprintf("dsse-install -plan %s -dir %s -organization <name>", planPath, dir),
			Needs:   "nothing — this is the first act, and it MINTS this deployment's authorities",
			Why: "A deployment has ONE anchor however many machines and regions it spans. Running this " +
				"again anywhere else mints a second, and a device that MOVES between them meets an issuer it " +
				"has never heard of.",
		},
		{
			Machine: minting.Name,
			// ★★★ IT SAYS WHERE TO RUN IT FROM (2026-09-02, found by walking this on a live deployment).
			// Every step for a JOINING machine begins `tar xzf … && cd /opt/dsse/<region> && docker compose`
			// and every step for the founding one did not — compose reads deployment.env and the compose
			// file from the working directory, so these worked only for a reader who had inferred the cd.
			Do:    fmt.Sprintf("cd %s && docker compose -p dsse --env-file deployment.env up -d", dir),
			Needs: "the directory above, on this machine",
			Why:   "Every other machine is packed from a deployment that is running, and joins one that answers.",
		},
		{
			Machine: minting.Name,
			// ★★★ THE ORDER PRINTS THE CAPTURING FORM, BECAUSE THE PLAIN ONE LOSES THE CREDENTIAL
			// (2026-09-04, lost it while walking three regions from the published tree). What this step
			// prints is shown ONCE and stored nowhere — the command says so, at length, in its own output.
			// But the order printed the command WITHOUT the pipe, so the operator who follows the order
			// exactly is the operator who reads that warning after the credential has already scrolled past.
			// A warning that arrives with the thing it warns about is not a warning. The pipe is now part of
			// the step, so following the order captures by default and the warning is a confirmation.
			Do: fmt.Sprintf("dsse-install -bootstrap-admin -dir %s -control-plane https://%s -admin-email <address> 2>&1 | tee admin-credentials.txt",
				dir, p.PlaneNamesFor(founding.ID)["admin"]),
			// ★ AND IT SAYS HOW TO KNOW THE PLANE IS ANSWERING (same walk, one step earlier). "The control
			// plane answering" was already the stated need, and this still failed on the first attempt —
			// `Post https://admin.…/admin/admins/invite: EOF`, run nine seconds after `up -d` returned. The
			// containers were started; the process inside was not listening yet, and the door in front of it
			// answered for it. An operator meeting that EOF has no way to tell it from a broken deployment.
			Needs: "the control plane answering, and the break-glass credential still armed — which it is " +
				"until this runs. ★ Started is not answering: the step above returns as soon as the " +
				"containers exist, and the process inside takes some seconds more, during which the region's " +
				"door answers for it and this step fails with EOF. Wait for the door to answer: " +
				"`until curl --fail --silent --show-error --cacert " + dir + "/deployment-anchor.pem https://" + p.PlaneNamesFor(founding.ID)["admin"] + "/healthz >/dev/null; do sleep 2; done`",
			Why: "A new deployment has no named principals, so start-control-plane.sh arms a credential that " +
				"authorises as owner and attributes every act to nobody. This creates a real administrator and " +
				"closes it. ★ RUN IT BEFORE PACKING ANY OTHER MACHINE: the marker and the fleet credential it " +
				"writes go into the directory every later machine is packed FROM, and a machine packed before " +
				"it is born answering 401 to its own control plane.",
		},
		{
			Machine: minting.Name,
			Do: fmt.Sprintf("cd %s && docker compose -p dsse --env-file deployment.env up -d --no-deps --force-recreate ",
				dir) + composeServiceList(controlPlaneNodeNames, edgeNodeNames),
			Needs: "the step above",
			Why: "The marker exists now, so the next start arms nothing — but the process running NOW still " +
				"has the break-glass credential armed. The restart is what closes it. " +
				"★★★ AND THE EDGES RESTART TOO (2026-08-31, measured: they did not). Closing the break-glass " +
				"credential changes what the FLEET presents, and an Edge still holding the old one is answered " +
				"401 on every pull while staying healthy on every screen — it keeps serving what it booted " +
				"with and never learns anything again. The deployment's own compose file has said this beside " +
				"the same act since 2026-08-26; this step restarted the control planes alone, so the founding " +
				"region's Edges sat at \"config-bundle sync: pull failed (keeping config): control plane " +
				"returned 401\" and knew none of the connectors the other regions had registered.",
		},
	}

	// ★ THE REST OF THE FOUNDING REGION, then each joining region: its control plane, then its Edges.
	regions := []PlanRegion{founding}
	for _, r := range p.Regions {
		if !r.Founding {
			regions = append(regions, r)
		}
	}
	for _, r := range regions {
		for _, m := range machinesInOrder(r) {
			if r.Founding && m.Name == minting.Name {
				continue // this directory IS that machine
			}
			needs, why := m.needsFor(r, founding, minting)
			// ★★★ A JOINING STATE-BEARING REGION IS ADMITTED TO THE STORE BEFORE IT STARTS, AND AS A LEARNER
			// (2026-08-31). Its machine renders one member of the deployment's one cluster, and a member that
			// was never added is a process that starts, finds itself unknown, and never joins.
			//
			// ★ AND THE ORDER OF THESE TWO IS THE WHOLE POINT. `member add` for a VOTING member changes the
			// quorum the instant it runs: a second voting member makes the quorum two, so if this machine then
			// fails to come up, the founding region's database goes read-only and there is no way back —
			// removing the member is itself a decision the store has to reach a quorum to make. A learner is
			// not counted, so the deployment is unharmed for as long as this takes, or forever if it never
			// works.
			if joinsTheStore(p, r, m) {
				steps = append(steps, PlanStep{
					Machine: minting.Name,
					Do: fmt.Sprintf("%s member add %s --learner --peer-urls=%s",
						storeExecPrefix(p, dir), storeMemberName(r.ID), p.storeMemberPeerURL(r)),
					Needs: "the founding region's store answering",
					Why: "This region keeps a copy of the database, so it holds a member of the deployment's " +
						"ONE consensus store. As a LEARNER it takes no part in the quorum: if the machine " +
						"below never comes up, nothing that works today stops working.",
				})
			}
			steps = append(steps,
				PlanStep{
					Machine: minting.Name,
					Do:      fmt.Sprintf("dsse-install -plan %s -dir %s -carry %s.tar.gz -machine %s", planPath, dir, m.Name, m.Name),
					Needs:   "the administrator to exist (the step above), so this machine is packed with the fleet credential",
					Why:     "A machine packed before that is born answering 401 on every pull, and goes on serving what it booted with.",
				},
				// ★★★ AND THEN SOMEBODY MOVES THE FILE, WHICH NO STEP USED TO SAY (2026-09-04, found by
				// following this order across three machines that had nothing on them). The step above writes
				// the archive on the MINTING machine; the step below untars it on ANOTHER one. Between them is
				// a copy across the network that the order simply did not contain, so the order read as though
				// the file arrived by itself and the next command failed with "Cannot open: No such file or
				// directory" — which reads as a packing failure and is not one.
				//
				// ★ IT IS ALSO THE MOST SENSITIVE FILE THIS DEPLOYMENT EVER PRODUCES OUTSIDE authority/: it
				// carries the region's identity and the fleet credential, so whoever holds a copy can be that
				// region. It is meant to travel once, over a channel the operator trusts, and be deleted from
				// wherever it stopped on the way.
				PlanStep{
					Machine: minting.Name,
					// ★ NAMED BY WHAT ACTUALLY RESOLVES, AND WITH NO LOGIN IN IT. The plan holds the name the
					// other machines reach this one by; it does not hold who you log in as, and a step that
					// asked would be a step needing somebody standing there. Written this way it is the
					// current user, which on a fleet built by one operator is the right one.
					Do:    fmt.Sprintf("scp %s.tar.gz %s:", m.Name, machineReachableName(m)),
					Needs: "a way to reach that machine — the archive does not travel by itself",
					Why: "The archive was written here and is needed there. It carries this region's identity " +
						"and the fleet credential, so anyone holding a copy can be this region: move it once, " +
						"over a channel you trust, and delete every copy it leaves behind.",
				},
				PlanStep{
					Machine: m.Name,
					Do:      fmt.Sprintf("mkdir -p /opt/dsse/%s && tar xzf %s.tar.gz -C /opt/dsse/%s && cd /opt/dsse/%s && docker compose -p dsse-%s --env-file deployment.env up -d", r.ID, m.Name, r.ID, r.ID, r.ID),
					Needs:   needs,
					Why:     why,
				})
			if joinsTheStore(p, r, m) {
				steps = append(steps, PlanStep{
					Machine: minting.Name,
					// ★★★ THE LOOKUP RUNS ON THE HOST, NOT IN THE CONTAINER (2026-08-31, measured: the etcd
					// image has no shell, so `exec … sh -c` failed with "sh: executable file not found").
					// The operator's own shell resolves $( ), which is where a shell certainly exists.
					Do: fmt.Sprintf("%[1]s member promote $(%[1]s member list | awk -F', ' '$3==\"%[2]s\"{print $1}')",
						storeExecPrefix(p, dir), storeMemberName(r.ID)),
					Needs: "the machine above running, and its member caught up with the cluster",
					Why: "Until this runs the member is a learner: it holds a copy and has no vote, so the " +
						"deployment tolerates no more failures than it did before this region existed. ★ The " +
						"server REFUSES to promote a learner that has not caught up, so a refusal here means " +
						"wait and run it again — it does not mean something is wrong. ★ AND REDUNDANCY " +
						"ARRIVES WITH THE THIRD PROMOTION, not the second: two voting members cannot lose one.",
				})
			}
		}
	}

	steps = append(steps, PlanStep{
		Machine: minting.Name,
		Do: fmt.Sprintf("dsse-install -verify -dir %s -control-plane https://%s -edge %s -edge-admin %s -control-plane-peers %s -admin-token <token>",
			dir, p.PlaneNamesFor(founding.ID)["admin"],
			strings.Join(p.verifyEdges(), ","), strings.Join(p.verifyEdgeAdmins(), ","),
			strings.Join(p.verifyControlPlanes(), ",")),
		// ★★★ AND WHERE IT IS RUN FROM DECIDES TWO OF ITS ANSWERS. Two checks ask what a DEVICE would get —
		// whether the region presents the name it announces, and whether the name an expired agent comes back
		// on leads anywhere — so they resolve those names the ordinary way. Run from a shell whose resolver
		// has never heard of this deployment, they report "no such host", which is a true sentence about the
		// shell and says nothing about the deployment; NAME@ADDRESS tells this installer where to dial and
		// cannot tell a device, so it does not answer them either. Following the line above on a machine with
		// no zone for the deployment yet therefore ends in two failures nobody can act on, which is the
		// procedure failing rather than the deployment.
		Needs: "every machine above, started, and a resolver that answers this deployment's names where you " +
			"run this. Two of these checks ask what a DEVICE would get, so they resolve the names the " +
			"ordinary way. Where there is no zone for them yet, run it from inside the deployment's own " +
			"network — the image carries this installer:\n" +
			"      docker run --rm --network <project>_default -v \"$PWD:/deployment\" \\\n" +
			"        --add-host <each name below>:<the front door's address, DSSE_FRONT_DOOR_A> \\\n" +
			"        --entrypoint dsse-install " + "$DSSE_IMAGE" + " -verify -dir /deployment …",
		Why: "Half of what -verify asks is about the FLEET — is more than one control plane running, does " +
			"every Edge hand devices the same region map, does every node run the same build — and a " +
			"deployment answering those from one node looks complete and is not.",
	})
	return steps
}

// machinesInOrder puts a region's control plane before its Edges: an Edge takes its configuration from the
// control plane of its own region and reports to it.
func machinesInOrder(r PlanRegion) []PlanMachine {
	out := []PlanMachine{}
	for _, m := range r.Machines {
		if m.Holds.has("control-plane") {
			out = append(out, m)
		}
	}
	for _, m := range r.Machines {
		if !m.Holds.has("control-plane") {
			out = append(out, m)
		}
	}
	return out
}

func (m PlanMachine) needsFor(r, founding PlanRegion, minting PlanMachine) (needs, why string) {
	if m.Holds.has("control-plane") {
		if r.Founding {
			return "the founding control plane, running", "It joins the deployment its sibling already stands up."
		}
		return fmt.Sprintf("%s's consensus store answering at %s:%d — from THIS machine, not from where it was packed",
				minting.Name, minting.reachableName(), planEtcdPortA),
			"A region that holds state joins the deployment's ONE consensus store. Started before it answers, " +
				"this region's database members elect among themselves and the deployment has two opinions " +
				"about which database is primary."
	}
	return fmt.Sprintf("the control plane of %s, running and reachable from here", r.ID),
		"An Edge takes its configuration and its organizations' material from the control plane, and refuses " +
			"to serve a fleet whose promises it cannot keep. Started first, it comes up serving nothing and " +
			"says so only in its own log."
}

// ★★★ EVERY ADDRESS IS THE ONE REACHABLE FROM WHERE THE COMMAND RUNS (2026-08-28, measured). The final check
// runs on the founding control plane, and it was given each machine's OWN address — which is that machine's
// private one. A private address in another region is routable from nowhere but that region, so the check
// that measures the FLEET could reach only half of it, on a deployment where every machine was answering.
//
// The plan holds both: a machine's own addresses, and where the other regions reach it. Which one to use is
// decided by where the command runs.
func (p *Plan) fromFounding(m PlanMachine, r PlanRegion, index int) string {
	if r.Founding {
		if index < len(m.Addresses) {
			return m.Addresses[index]
		}
		return m.Addresses[0]
	}
	// Another region: the address it publishes to the others. There is one, so both of its doors are behind
	// it — which is what a second address in another region would need its own of.
	return m.reachableAt()
}

func (p *Plan) verifyEdges() []string {
	out := []string{}
	for _, r := range p.Regions {
		agents := p.PlaneNamesFor(r.ID)["agents"]
		for _, m := range r.Machines {
			if !m.Holds.has("edges") {
				continue
			}
			// ★★★ ONE DOOR PER MACHINE, SO ONE ADDRESS (2026-09-02). The founding region was asked at EVERY
			// address it holds, from when a region's doorway was a PAIR and the second address was the
			// second door. The operator retired the pair — "for both connectors and agents the destination
			// IP is one per region, and that is the haproxy" — and this went on asking, so a deployment that
			// is exactly what was asked for reported
			//
			//	FAIL a front door leads to this deployment ... dial tcp 10.21.1.168:443: connection refused
			//
			// twice, about an address nothing is meant to answer on any more.
			out = append(out, "https://"+agents+"@"+p.fromFounding(m, r, 0))
		}
	}
	return out
}

func (p *Plan) verifyEdgeAdmins() []string {
	out := []string{}
	for _, r := range p.Regions {
		for _, m := range r.Machines {
			if !m.Holds.has("edges") {
				continue
			}
			for _, node := range edgeNodeNames {
				// ★ THE REGION IS PART OF THE NODE'S NAME: every region runs services of the same names, so
				// without it two machines in two regions answer to one.
				out = append(out, "https://"+r.ID+"-"+node+".admin."+p.Deployment+"@"+p.fromFounding(m, r, 0))
			}
		}
	}
	return out
}

func (p *Plan) verifyControlPlanes() []string {
	out := []string{}
	for _, r := range p.Regions {
		cp := r.controlPlane()
		for _, node := range controlPlaneNodeNames {
			out = append(out, "https://"+r.ID+"-"+node+".admin."+p.Deployment+"@"+p.fromFounding(cp, r, 0))
		}
	}
	return out
}

// machineReachableName is the name other machines reach this one by, falling back to the machine's own name
// when a plan does not give one (a single-machine deployment never needs to be reached from elsewhere).
func machineReachableName(m PlanMachine) string {
	if r := strings.TrimSpace(m.Reachable); r != "" {
		return r
	}
	return m.Name
}

// PrintInstallOrder writes the order out, which is the thing an operator follows with nobody helping.
func PrintInstallOrder(p *Plan, dir, planPath string) {
	// ★★★ AN ORDER WITH A BLANK IN IT IS NOT AN ORDER (2026-09-04, found by printing the order for three
	// regions before choosing a directory — which is exactly when an operator prints it). -dir is optional
	// here, so it was substituted empty, and half the steps came out as commands that run and do the wrong
	// thing rather than commands that fail:
	//
	//	cd  && docker compose -p dsse --env-file deployment.env up -d
	//
	// `cd` with no argument is `cd $HOME`. The operator who pastes that line is in their home directory
	// looking for a compose file that is somewhere else. Nothing refused, nothing said why. A placeholder
	// that cannot be pasted is better than a blank that can.
	if strings.TrimSpace(dir) == "" {
		dir = "<dir>"
	}
	fmt.Printf("★ %s — %d region(s), %d machine(s). Do these in this order.\n\n",
		p.Deployment, len(p.Regions), len(p.MachineNames()))
	for i, s := range p.InstallOrder(dir, planPath) {
		fmt.Printf("%2d. on %s\n", i+1, s.Machine)
		fmt.Printf("      %s\n", s.Do)
		fmt.Printf("    needs: %s\n", s.Needs)
		fmt.Printf("    why:   %s\n\n", wrapAt(s.Why, 96, "           "))
	}
}

func wrapAt(text string, width int, indent string) string {
	words, line, out := strings.Fields(text), "", []string{}
	for _, w := range words {
		if len(line)+len(w)+1 > width {
			out = append(out, line)
			line = w
			continue
		}
		if line == "" {
			line = w
		} else {
			line += " " + w
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return strings.Join(out, "\n"+indent)
}

// joinsTheStore reports whether this machine holds a member of the deployment's consensus store that has to
// be admitted to it first: a control-plane machine, in a region that keeps state, in a deployment whose store
// spans regions. The founding region's member is not admitted — it IS the cluster the others are admitted to.
// etcdctlAt is how to reach the deployment's store from inside the founding member's container.
//
// ★★★ THE PRINTED COMMAND HAS TO WORK ONCE THE STORE SPEAKS TLS (2026-08-31, measured: it did not). etcdctl
// defaults to 127.0.0.1:2379 in PLAINTEXT, so with TLS on it fails with "error reading server preface: EOF" —
// a message that names neither TLS nor the endpoint it used. And the loopback address cannot be verified
// against a certificate issued for the member's NAME, so the endpoint has to be the name, at the published
// port. No client certificate: the client endpoint asks for none.
func etcdctlAt(p *Plan) string {
	founding := p.foundingRegion().controlPlane()
	return fmt.Sprintf("etcdctl --endpoints=https://%s:%d --cacert=/deployment/store-ca.pem",
		founding.reachableName(), planEtcdPortA)
}

// storeExecPrefix is the whole invocation up to the etcdctl subcommand: the compose exec, and the endpoint
// and CA that reach a store speaking TLS.
func storeExecPrefix(p *Plan, dir string) string {
	// ★ AND THESE RUN FROM THE FOUNDING DIRECTORY TOO. Same reason as the steps above: compose finds the
	// deployment by the working directory, and the operator was not told which one.
	return "cd " + dir + " && docker compose -p dsse --env-file deployment.env exec -T dsse-store-a " +
		etcdctlAt(p)
}

func joinsTheStore(p *Plan, r PlanRegion, m PlanMachine) bool {
	return !r.Founding && r.HoldsState && m.Holds.has("control-plane") && len(p.stateBearingRegions()) > 1
}
