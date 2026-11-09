package main

import (
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// startupRecheck schedules the early passes described in Execute: at most len(startupRecheckDelays) of them,
// each only while a refusal stands.
type startupRecheck struct {
	reportsDir string
	done       int
}

var startupRecheckDelays = []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute}

func (r *startupRecheck) next() <-chan time.Time {
	if r.done >= len(startupRecheckDelays) || !agentupdate.RefusalStands(r.reportsDir) {
		return nil
	}
	d := startupRecheckDelays[r.done]
	r.done++
	return time.After(d)
}

// keylessFirstPassDelay is how long a service that started holding NO update-signing key waits before its first
// pass.
//
// ★★ THE INSTALLER STARTS THIS SERVICE BEFORE IT HANDS OVER THE KEYS (2026-11-06, measured on a fresh install in
// a three-region acceptance). StartServices runs before provisioning puts the deployment's keys in force and
// restarts the service with them, five seconds later. The keyless process's first pass refused ("no trusted
// update-signing keys are configured") and reported it, and the Devices screen went on saying "refusing the
// update" about a device that had been given its keys seconds afterwards. A keyless start now waits: during an
// install the restart ends this process first and nothing is refused; a device that is genuinely given no key
// still reports the refusal, two minutes later.
const keylessFirstPassDelay = 2 * time.Minute

// firstPassDelay is zero for a service that holds at least one update-signing key.
func firstPassDelay(keys int) time.Duration {
	if keys > 0 {
		return 0
	}
	return keylessFirstPassDelay
}
