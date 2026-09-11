//go:build windows

package main

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// keepAskingForPosture retries the control plane's signed steering posture after the ONE fetch at start-up
// failed, and says what it finds.
//
// ★★ THE POSTURE WAS FETCHED ONCE AND NEVER AGAIN (2026-08-21, raised from the Edge side after they found the
// same shape three times in their own tree, and confirmed here). If that single fetch failed — the Edge
// restarting, a name not yet resolving, a network not yet up — the device kept its BOOTSTRAP flags for the
// whole life of the process and said so exactly once, in a line an operator reads at boot and never again.
// This box did precisely that on 2026-08-20: the fetch failed on an unrelated naming defect and the boot ran
// on install-time flags while the control plane had decided otherwise. The naming defect was the cause that
// day; never asking again is the defect that made it durable.
//
// ★ IT REPORTS, IT DOES NOT SWITCH. Region failover decides whether the region machinery is BUILT, and the
// capture is armed from these values, so flipping them under a running data path would be a second, worse
// class of bug — a device changing how it steers because a fetch finally succeeded, mid-flight, with filters
// already in the kernel. What an operator needs from a device in this state is to know it is in it. So this
// keeps asking until it gets an answer, then compares that answer with what is actually in force and stays
// LOUD while the two disagree. Silently running on flags the control plane has overruled is the state this
// removes; applying them live is a change that needs its own design.
// ★★★ IT RE-ASKS EVERY REGION, NOT ONE ADDRESS (2026-08-30). This loop exists only because the first fetch
// failed, and on a two-site deployment that means the home region is down — so a retry pinned to the home
// address is a minute-by-minute re-ask of the machine that is not there. The device measured on win-dev-1 stayed
// dark for the whole four-minute outage doing exactly that. Same plan, same verification, same order: the
// address in force first, and nothing else dialled when it answers.
func keepAskingForPosture(tc transportConfig, plan []posturedEndpoint, pinHex, keyStateDir string, inForce resolvedPosture,
	bootFailOpen, bootRegion bool, bootCooldown time.Duration, stop <-chan struct{}) {
	if !tc.enabled || strings.TrimSpace(pinHex) == "" || len(plan) == 0 {
		return
	}
	go func() {
		// A nil stop channel means "for the life of the process", which is what a service is: the select below
		// simply never takes that branch.
		// A minute matches the other loops this agent runs against the Edge; the device is not stuck, it is
		// running on the wrong side of a decision, and that is worth re-asking about at the same cadence as
		// everything else rather than hammering.
		const every = time.Minute
		for {
			select {
			case <-stop:
				return
			case <-time.After(every):
			}
			posture, from, idx, err := fetchPostureFromAnyRegion(tc, plan,
				policyVerificationKeys(pinHex, keyStateDir), 8*time.Second)
			if err != nil {
				continue // still unreachable or unverifiable; the start-up line already said we are on boot flags
			}
			if idx > 0 {
				log.Printf("steer: the steering posture was reached at %s%s on retry — the address in force is "+
					"still not answering", from.BaseURL, regionLabelSuffix(from.Region))
			}
			matched, line := posturePlanAfterRetry(inForce, applyCPPosture(bootFailOpen, bootRegion, bootCooldown, posture))
			log.Print(line)
			if matched {
				return
			}
		}
	}()
	log.Printf("steer: CP steering-posture will be re-asked every minute (the start-up fetch failed; this " +
		"device is running its install-time flags until it is told otherwise)")
}

// posturePlanAfterRetry decides what a late-arriving posture means, and says it in one line.
//
// matched=true ends the retry: the boot-time failure cost this device nothing. matched=false keeps it going,
// because the difference persists until a restart and an operator who saw the boot line once will not see it
// again — so the device has to go on saying which side of the decision it is running on.
func posturePlanAfterRetry(inForce, want resolvedPosture) (matched bool, line string) {
	if want == inForce {
		return true, "steer: CP steering-posture reached on retry and MATCHES what is in force " +
			"(region_failover/cooldown) — the boot-time failure cost this device nothing"
	}
	return false, fmt.Sprintf("steer: ★ CP steering-posture DIFFERS from what this device is running: "+
		"in force region_failover=%v terminal_fail_open=%v cooldown=%s — control plane says "+
		"region_failover=%v terminal_fail_open=%v cooldown=%s. The start-up fetch failed, so this device "+
		"kept its install-time flags. RESTART THE AGENT to apply the control plane's decision.",
		inForce.RegionFailover, inForce.TerminalFailOpen, inForce.Cooldown,
		want.RegionFailover, want.TerminalFailOpen, want.Cooldown)
}
