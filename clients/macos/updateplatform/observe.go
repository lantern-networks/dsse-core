// Package updateplatform is the macOS half of agentupdate.Platform.
//
// The sequencing, the gate and the journal are platform-agnostic and already written; what a platform supplies
// is the doing. This is the second implementation of that interface, and writing it is what turns the
// interface's promises from "what Windows does" into rules — the RunningVersion contract and the InUse
// contract were both written after Windows found that a spec describing one mechanism does not survive contact
// with a second platform.
//
// ★ WHAT IS DIFFERENT HERE, AND IT IS NOT COSMETIC. On Windows the WFP driver holds the redirect in the
// kernel, so an agent that dies leaves the machine black-holed and Disarm is a real, dangerous, necessary
// step. macOS has no equivalent: an NEAppProxyProvider that stops is a provider the system stops routing to,
// and this deployment does not steer DNS either. So the disarm-before-update step is not merely unnecessary
// here — implementing it would be a no-op wearing the costume of a safety measure. See DisarmBeforeUpdate.
//
// observe.go holds the parts with no exec in them, so the parsing and the folding are exercised on any host
// against output captured from a real Mac.
package updateplatform

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// screenLockState is what the console session says about itself.
type screenLockState int

const (
	// lockUnknown: the question could not be answered. Never treated as "nobody is here".
	lockUnknown screenLockState = iota
	lockLocked
	lockUnlocked
	// lockNoConsoleUser: nobody is logged in at the display at all.
	lockNoConsoleUser
)

// parseScreenLocked reads `ioreg -n Root -d1 -k CGSSessionScreenIsLocked`.
//
// ★ THE ABSENCE OF THE KEY IS THE ANSWER, and that is the trap in this API. macOS publishes
// CGSSessionScreenIsLocked only WHILE the screen is locked; on an unlocked Mac the key is simply not there.
// Measured on this machine, 2026-08-10: unlocked produced no matching line at all.
//
// So a naive reader that greps for the key and finds nothing concludes "not locked", which is right, and a
// naive reader whose ioreg call FAILED also finds nothing and concludes the same thing, which is the dangerous
// version of the same answer. The two are separated by the caller passing whether the command succeeded — an
// unreadable ioreg is lockUnknown, and unknown never becomes permission.
// markerFutureTolerance is the clock skew a heartbeat may carry before it stops being believable. Small,
// because the two machines here are the same machine — the only spread is between one write and the next read.
const markerFutureTolerance = 2 * time.Minute

func parseScreenLocked(ioregOutput string, ioregOK bool, consoleUser string) screenLockState {
	if !ioregOK {
		return lockUnknown
	}
	// Nobody at the display: root or an empty console owner means no GUI session. Checked BEFORE the lock
	// state, because an unattended login window reports no lock key either and "nobody is logged in" is a
	// stronger and more useful answer than "not locked".
	switch strings.TrimSpace(consoleUser) {
	case "", "root":
		return lockNoConsoleUser
	}
	for _, line := range strings.Split(ioregOutput, "\n") {
		if !strings.Contains(line, "CGSSessionScreenIsLocked") {
			continue
		}
		// `"CGSSessionScreenIsLocked" = Yes` on the machines that publish it as a boolean, `= 1` elsewhere.
		v := strings.ToLower(strings.TrimSpace(line[strings.LastIndex(line, "=")+1:]))
		if v == "yes" || v == "true" || v == "1" {
			return lockLocked
		}
		return lockUnlocked
	}
	return lockUnlocked
}

// inUse folds the lock state into the predicate agentupdate.DeviceConditions.InUse means.
//
// The contract on that field is the one written after Windows: InUseKnown only when this platform can speak
// for every interactive session, and the guess never made is "nobody is here". macOS has exactly one console
// session, which makes the folding simpler than Windows' and the rule identical.
func inUse(state screenLockState) (bool, bool) {
	switch state {
	case lockLocked, lockNoConsoleUser:
		return false, true
	case lockUnlocked:
		return true, true
	default:
		return false, false
	}
}

// parseHIDIdle reads `ioreg -c IOHIDSystem` and returns time since the last human input.
//
// ★ THIS WORKS HERE AND IS THE OPPOSITE OF WINDOWS. HIDIdleTime is nanoseconds since the last HID event and it
// is maintained on a normal Mac — measured on this machine at 45.7 s while it sat idle. On Windows the
// equivalent (WTSINFOEX's LastInputTime) comes back ZERO for the console session, which is why the plan's
// default sets RequireIdleMinutes to 0 and expresses the operator's intent as RequireUnattended instead.
//
// So a fleet with both platforms can satisfy an idle-minutes window on its Macs and not on its Windows boxes.
// That asymmetry belongs in the operator's plan rather than being hidden by one platform inventing a number:
// this returns known=false when the value is absent or nonsensical, and the gate refuses on an unknown.
func parseHIDIdle(ioregOutput string, ioregOK bool) (time.Duration, bool) {
	if !ioregOK {
		return 0, false
	}
	// Several IOHIDSystem nodes can report; the SMALLEST is the most recent input anywhere on the machine,
	// which is the same "shortest across sessions" rule the Windows side folds with.
	shortest := time.Duration(1<<63 - 1)
	found := false
	for _, line := range strings.Split(ioregOutput, "\n") {
		i := strings.Index(line, "\"HIDIdleTime\"")
		if i < 0 {
			continue
		}
		eq := strings.Index(line[i:], "=")
		if eq < 0 {
			continue
		}
		raw := strings.TrimSpace(line[i+eq+1:])
		raw = strings.Trim(raw, " \t\"")
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			continue
		}
		d := time.Duration(n) * time.Nanosecond
		if d < shortest {
			shortest = d
		}
		found = true
	}
	if !found {
		return 0, false
	}
	return shortest, true
}

// parseACPower reads `pmset -g batt`.
//
// A desktop with no battery prints "Now drawing from 'AC Power'" and nothing else, which is a definite yes.
// Anything unrecognised is UNKNOWN rather than assumed: the gate refuses to update on an unknown power state,
// and inventing "probably plugged in" would defeat a check somebody deliberately turned on.
func parseACPower(pmsetOutput string, pmsetOK bool) (bool, bool) {
	if !pmsetOK {
		return false, false
	}
	l := strings.ToLower(pmsetOutput)
	switch {
	case strings.Contains(l, "'ac power'"), strings.Contains(l, "\"ac power\""):
		return true, true
	case strings.Contains(l, "'battery power'"), strings.Contains(l, "\"battery power\""):
		return false, true
	default:
		return false, false
	}
}

// runtimeMarker is what the running system extension records about itself, and the macOS answer to
// RunningVersion.
//
// ★ THE RULE, restated because this is the platform that had to satisfy it rather than define it: a version
// counts as running only when it is paired with an INDEPENDENT liveness signal for the process that reported
// it. Windows pairs a static registry value with the SCM, because the value itself says nothing about whether
// anyone is still there.
//
// Here the marker carries its own refreshed heartbeat, which is a STRONGER signal than the Windows one rather
// than a weaker substitute: a static value survives the process that wrote it, and a timestamp that stopped
// advancing cannot be produced by a process that is gone. The extension refreshes it on the heartbeat timer it
// already runs.
type runtimeMarker struct {
	Version     string `json:"version"`
	PID         int    `json:"pid"`
	StartedAt   string `json:"started_at"`
	HeartbeatAt string `json:"heartbeat_at"`
	// DeviceIdentity and TenantID are what the running extension read off its verified (T) client certificate.
	// They are here so the updater — which holds no network identity of its own, deliberately — can check that
	// a plan addressed to a device is addressed to THIS one. Empty on a build that predates them.
	DeviceIdentity string `json:"device_identity"`
	TenantID       string `json:"tenant_id"`
}

// markerStaleAfter is how long a marker may go unrefreshed before it stops counting as a running agent.
//
// Three heartbeat intervals (the extension refreshes every 15 s). Long enough that a busy moment or a clock
// hiccup does not make a healthy agent vanish; short enough that a killed extension stops being credited with
// running a version within a minute — which matters, because the whole point of the pairing is that a version
// nobody is running must not gate an update.
const markerStaleAfter = 45 * time.Second

// resolveRunningVersion applies the rule to a marker.
//
// The three outcomes mirror the Windows ones deliberately, so an operator reading a mixed fleet sees one
// vocabulary: a live agent reports its version, a dead one reports not-running, and an agent too old to write
// a marker at all is its own case — it needs an INSTALL, not a recovery, and it cannot get one from an updater
// gated on the answer it cannot give.
func resolveRunningVersion(m runtimeMarker, present bool, now time.Time) (string, error) {
	if !present {
		// No marker and no way to tell whether that is a dead agent or one predating the marker. Reported as
		// not-running, which is the outcome that refuses WITHOUT recording a failure — so a device is reassessed
		// on the next tick rather than poisoning a version that was never the problem.
		return "", fmt.Errorf("%w: no runtime marker on this device", errAgentNotRunning)
	}
	beat, err := time.Parse(time.RFC3339, strings.TrimSpace(m.HeartbeatAt))
	if err != nil {
		return "", fmt.Errorf("%w: the runtime marker's heartbeat %q is unreadable, so whether anything is running "+
			"cannot be established", errAgentNotRunning, m.HeartbeatAt)
	}
	// ★ A HEARTBEAT FROM THE FUTURE NEVER GOES STALE (2026-08-13, twenty-ninth review). now.Sub(beat) is
	// NEGATIVE when the marker was written while the clock was ahead — an NTP correction afterwards leaves an
	// age that counts down instead of up, so a dead agent goes on reporting itself alive for the whole skew.
	// A timestamp this device cannot have produced yet is not evidence of life; it is a clock this device
	// cannot trust, which is the same answer as no evidence.
	if beat.After(now.Add(markerFutureTolerance)) {
		return "", fmt.Errorf("%w: the runtime marker's heartbeat is %s in the FUTURE, so it cannot be used to "+
			"tell whether anything is running (a clock correction after it was written looks exactly like this)",
			errAgentNotRunning, beat.Sub(now).Round(time.Second))
	}
	if age := now.Sub(beat); age > markerStaleAfter {
		v := strings.TrimSpace(m.Version)
		if v == "" {
			return "", fmt.Errorf("%w: the runtime marker stopped being refreshed %s ago", errAgentNotRunning,
				age.Round(time.Second))
		}
		// The stale value goes in the PROSE and is never returned as the answer — the same shape as the Windows
		// message, and for the same reason: it is useful to a human and dangerous to a machine.
		return "", fmt.Errorf("%w: the runtime marker stopped being refreshed %s ago (it last recorded %s, which "+
			"is a memory and not a running version)", errAgentNotRunning, age.Round(time.Second), v)
	}
	v := strings.TrimSpace(m.Version)
	if v == "" {
		return "", fmt.Errorf("%w: the extension is running and recorded no version", errRunningVersionUnknown)
	}
	return v, nil
}
