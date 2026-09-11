package main

import (
	"flag"
	"fmt"
	"runtime"
)

// ★ WHY A GO PROCESS CAPS ITSELF BELOW THE MACHINE (operator decision 2026-08-19, #35).
//
// The question was whether the admin plane survives a saturated data plane. On this node it does not survive
// by accident: the Edge, the control plane, the Console and Postgres are separate processes on ONE host, and
// nothing stops the Edge from taking every core. When it does, the plane an operator needs in order to SEE
// the saturation — sign in, read the fleet, block a device — is starved by the plane that is saturating.
//
// The reservation is honest about what it is and is not:
//
//	IT DOES     bound how much of the host the Edge can consume, so the admin path's own processes (control
//	            plane, Console, Postgres) still get scheduled while the data plane is flat out.
//	IT DOES NOT partition CPU between the admin and data planes INSIDE this process. Both are goroutines in
//	            one runtime; Go's scheduler is preemptive and already interleaves them. Anyone reading this
//	            expecting an admin-only core will not find one, and should not add one here.
//
// Separate admin listeners already exist (-admin-listen). Listener separation is not scheduling separation,
// which is why this is a second, different mechanism rather than a duplicate of that one.
const cpuHeadroomMinimumCoresBeforeReserving = 4

// cpuHeadroomPlan decides the GOMAXPROCS this process should run with. Pure, so the rule can be gated without
// touching the runtime.
//
// requested < 0 means "decide for me": reserve exactly one core on a machine big enough for it to matter, and
// nothing on a small one — halving a two-core node to protect an admin plane makes the outage arrive sooner.
func cpuHeadroomPlan(availableCores, requested int) (procs int, reserved int, reason string) {
	if availableCores < 1 {
		availableCores = 1
	}
	switch {
	case requested < 0:
		if availableCores >= cpuHeadroomMinimumCoresBeforeReserving {
			reserved = 1
			reason = fmt.Sprintf("default: reserving 1 of %d cores for the admin plane's own processes", availableCores)
		} else {
			reason = fmt.Sprintf("default: %d core(s) is too few to reserve from — taking a core away would bring the outage on sooner", availableCores)
		}
	case requested == 0:
		reason = "explicitly disabled: this process may use every core on the node"
	default:
		reserved = requested
		reason = fmt.Sprintf("configured: reserving %d of %d cores for the admin plane's own processes", requested, availableCores)
	}
	procs = availableCores - reserved
	if procs < 1 {
		// Never reserve the node out of a data plane. A request that would leave nothing is honoured as far as
		// it can be and SAYS so, rather than silently becoming something else.
		procs = 1
		reserved = availableCores - 1
		reason = fmt.Sprintf("%s — clamped: %d core(s) available, so this process keeps 1", reason, availableCores)
	}
	return procs, reserved, reason
}

// applyCPUHeadroom sets GOMAXPROCS per the plan and returns the line to log. Returns the previous value so a
// caller can report what actually changed rather than what was asked for.
func applyCPUHeadroom(requested int) string {
	available := runtime.NumCPU()
	procs, reserved, reason := cpuHeadroomPlan(available, requested)
	previous := runtime.GOMAXPROCS(procs)
	if reserved == 0 {
		return fmt.Sprintf("cpu headroom: none reserved (GOMAXPROCS %d -> %d of %d cores) — %s", previous, procs, available, reason)
	}
	return fmt.Sprintf("cpu headroom: %d core(s) reserved (GOMAXPROCS %d -> %d of %d cores) — %s; "+
		"this keeps the admin plane's OWN PROCESSES schedulable when the data plane is flat out, and does not "+
		"give admin requests inside this process a core of their own",
		reserved, previous, procs, available, reason)
}

// The flag lives here rather than in main.go: new flag definitions belong in a sibling file (the main.go
// decomposition ratchet), and this one belongs next to the rule it configures anyway.
var cpuHeadroomCoresFlag = flag.Int("cpu-headroom-cores", -1,
	"cores to leave unused by this process so the admin plane's own processes (control plane, Console, database) "+
		"stay schedulable while the data plane is saturated. -1 = reserve 1 on a node with 4+ cores and none on a "+
		"smaller one; 0 = reserve nothing. This does NOT reserve a core for admin requests inside this process")
