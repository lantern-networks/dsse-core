// Package runstate answers one question for a SECOND process: what version of the steering agent is running
// on this box right now?
//
// WHY IT EXISTS. The updater has to know the version of the code currently EXECUTING — not what is on disk —
// because the box that holds new bytes and runs old ones is the entire reason that distinction was drawn. On
// Windows the value it needs is computed by agentVersion() in the steer command's own `package main`, behind
// //go:build windows, from link-time ldflags. It is unexported, in another binary, and nothing exposed it: the
// agent has no --version flag, the opt-in /status endpoint carries no version field, and the only place the
// value reached the outside world was the heartbeat to the Edge. So DsseUpdater could not call it, as
// win-dev-1 found when it tried.
//
// WHAT MUST NOT BE DONE INSTEAD. Running the on-disk binary to ask its version answers the wrong question: it
// reports the on-disk version, which is correct on every healthy box and wrong on exactly the boxes this
// mechanism exists for. That is why the value is written by the LIVE process and never derived from the file.
//
// THE RULE THIS PACKAGE ENFORCES. A version counts as running only when it is paired with an INDEPENDENT
// liveness signal for the process that reported it. The registry value is a memory — a crashed agent leaves
// its last version behind — and a memory read as a fact is how an update gets gated on a build nobody is
// running. Here the memory is the value under the service's Parameters key and the liveness is the SCM's view
// of DsseSteer; the two are combined by Resolve, which is pure and therefore tested on any host.
//
// The decoding and the rule live in this file with no Windows API in them, deliberately: the reasoning that
// decides whether a device is eligible for a privileged code execution should not go unexercised because the
// test host was the wrong OS.
package runstate

import (
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// KeyPath is where the running agent records itself: the DsseSteer service's own Parameters key.
//
// Under the service's key rather than a key of our own, for the same reason driversvc records PENDING_REBOOT
// there: it inherits the Services ACL (SYSTEM and Administrators write, everyone reads) instead of needing one
// authored, and it is removed when the service is removed — so an uninstalled agent cannot leave a version
// behind for something else to read as current.
const KeyPath = `SYSTEM\CurrentControlSet\Services\DsseSteer\Parameters`

// Value names under KeyPath. RunningVersion is the answer; the other two are diagnostics and are explicitly
// NOT the liveness signal — see Resolve.
const (
	ValueRunningVersion = "RunningVersion"
	// ValueDeviceIdentity and ValueTenantID are who the running agent proved itself to be, from its verified
	// (T) client certificate.
	//
	// ★ They exist so the UPDATER — a separate process that deliberately holds no network identity — can check
	// that a plan addressed to a device is addressed to THIS one. A rollout plan names its addressee and the
	// Edge signs one per device, so without this a validly signed plan for a machine in an earlier wave opens
	// this machine's wave. The macOS side records the same two facts in its runtime marker, for the same reason.
	ValueDeviceIdentity = "DeviceIdentity"
	ValueTenantID       = "TenantID"
	ValueRunningPID     = "RunningPID"
	ValueRunningSince   = "RunningSince" // RFC3339, re-stamped by each write during this process's startup
)

// Record is what was read from the box, before the rule is applied. Every field is exactly as stored: the
// interpretation happens in Resolve, so a caller cannot accidentally use the raw value as the answer.
type Record struct {
	Version string
	PID     uint32
	Since   string
	// Present is false when there is no record at all. Distinguished from an empty Version because "the agent
	// never wrote one" and "the agent wrote an empty string" are different bugs.
	Present bool
}

// Liveness is the second, independent half of the answer: the SCM's view of the DsseSteer service.
type Liveness struct {
	Running bool
	// Known is false when the service manager could not be queried. That is a fault, not an answer, and Resolve
	// refuses to turn it into one.
	Known bool
	// Starting is the service in START_PENDING: it has been launched and has not finished coming up.
	//
	// It is separated from Running because collapsing the two produces a WRONG DIAGNOSIS rather than a missed
	// tick. The watchdog counts START_PENDING as running, correctly — it must not "recover" an agent that is
	// merely starting. But this package's question is different: a starting agent has not necessarily reached
	// runstate.Write yet, so "running, and no version recorded" would fire, and that case means "this agent
	// predates the marker and must be re-installed". Telling an operator to re-install a box that was simply
	// mid-startup is worse than saying nothing, and it is the kind of wrong that gets acted on.
	Starting bool
}

// Resolve applies the rule and returns the version of the code actually running.
//
// The four cases, and why each answers the way it does:
//
//   - the SCM could not be queried — a fault. Returning "not running" here would let one failed API call skip a
//     box from a rollout while reporting the box as the problem.
//   - the service is not running — agentupdate.ErrAgentNotRunning, whatever the stored value says. The stored
//     value IS included in the message, because "the last agent to run here was 0.1.0" is useful to a human and
//     dangerous to a machine; putting it in prose gives the diagnosis without offering it as data.
//   - running, no version recorded — agentupdate.ErrRunningVersionUnknown: this box needs an install, not an
//     update, and cannot get one from the updater.
//   - running, version recorded — the answer.
//
// The third case deserves its own sentence. A box whose agent runs but records nothing is running an agent
// OLDER than this mechanism, so the DSSE updater cannot update it and cannot bootstrap itself out of that: the
// first install carrying the marker has to arrive by MDM or by hand. That is the same bootstrap as the rollback
// stash (rollbackstore: a box installed months ago has no MSI to roll back to and refuses every update until an
// install leaves one). Reporting it through its own sentinel is what lets those devices be COUNTED instead of
// looking like a rollout that inexplicably stalls at some percentage.
func Resolve(rec Record, live Liveness) (string, error) {
	if !live.Known {
		return "", fmt.Errorf("runstate: could not determine whether the DsseSteer service is running, so the " +
			"running version cannot be established")
	}
	// START_PENDING is answered before Running, and answered as "not running yet" rather than as a verdict. The
	// consequence is deliberately identical to a stopped agent — ErrAgentNotRunning refuses WITHOUT recording a
	// failure, so a device caught mid-startup is skipped for this tick and reassessed on the next one, which is
	// exactly right for a state that resolves itself in seconds.
	if live.Starting {
		return "", fmt.Errorf("%w (the DsseSteer service is still starting, so it may not have recorded its "+
			"version yet; this device is skipped rather than judged)", agentupdate.ErrAgentNotRunning)
	}
	if !live.Running {
		if v := strings.TrimSpace(rec.Version); v != "" {
			return "", fmt.Errorf("%w (the last agent to run here recorded %s, which is a memory and not a "+
				"running version)", agentupdate.ErrAgentNotRunning, v)
		}
		return "", agentupdate.ErrAgentNotRunning
	}
	v := strings.TrimSpace(rec.Version)
	if v == "" {
		if !rec.Present {
			return "", fmt.Errorf("%w: the DsseSteer service is running but has recorded nothing under %s, so this "+
				"agent predates the running-version marker. It must be re-installed (MDM or a manual MSI) before "+
				"the DSSE updater can act on this device", agentupdate.ErrRunningVersionUnknown, KeyPath)
		}
		return "", fmt.Errorf("%w: %s\\%s is present but empty", agentupdate.ErrRunningVersionUnknown, KeyPath, ValueRunningVersion)
	}
	return v, nil
}
