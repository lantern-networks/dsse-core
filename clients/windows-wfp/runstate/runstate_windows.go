//go:build windows

// runstate_windows.go — the registry half: the agent writes, the updater reads.
//
// Everything that decides anything is in runstate.go and is tested off-Windows. What is here is the four
// syscalls that cannot be.
package runstate

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Write records the version of the code that is running, and is called by the agent AT STARTUP, from the live
// process, with the value that process's own agentVersion() computed.
//
// That is the whole point and the reason it is not derived from the file: the same function that stamps this
// value also produces the version the installer stashes rollback material under, so the two agree by
// construction rather than by two string literals in a .wxs and a .go file matching.
//
// Best-effort. An agent that refused to steer because it could not write a version marker would be trading
// enforcement for bookkeeping; the failure is printed and the updater reports the device as unassessable, which
// is the honest consequence.
func Write(version string) { WriteWithIdentity(version, "", "") }

// WriteWithIdentity records the running version AND who this agent proved itself to be. Empty identity or
// tenant are written as empty values rather than skipped, so "this build does not record it" stays visible to
// the reader instead of looking like a device with no identity.
func WriteWithIdentity(version, deviceIdentity, tenantID string) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, KeyPath, registry.SET_VALUE)
	if err != nil {
		fmt.Printf("runstate: could not record the running version under %s: %v — the DSSE updater will report "+
			"this device as unassessable until this succeeds\n", KeyPath, err)
		return
	}
	defer k.Close()
	if err := k.SetStringValue(ValueRunningVersion, version); err != nil {
		fmt.Printf("runstate: could not write %s: %v\n", ValueRunningVersion, err)
		return
	}
	// Diagnostics only. Neither is the liveness signal — see Resolve — and nothing must start treating them as
	// one: a PID can be reused, and a timestamp says when a process started, not that it is still there.
	_ = k.SetDWordValue(ValueRunningPID, uint32(os.Getpid()))
	_ = k.SetStringValue(ValueRunningSince, time.Now().UTC().Format(time.RFC3339))
	// Best-effort like the rest: an agent must not refuse to steer over bookkeeping. A missing value makes the
	// updater report that it could not confirm the plan is addressed to this device, which is the honest
	// consequence and is visible in --status.
	_ = k.SetStringValue(ValueDeviceIdentity, deviceIdentity)
	_ = k.SetStringValue(ValueTenantID, tenantID)
}

// Addressing reports who the running agent proved itself to be, or empty strings when it did not record it.
func Addressing() (deviceIdentity, tenantID string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, KeyPath, registry.QUERY_VALUE)
	if err != nil {
		return "", ""
	}
	defer k.Close()
	d, _, _ := k.GetStringValue(ValueDeviceIdentity)
	t, _, _ := k.GetStringValue(ValueTenantID)
	return strings.TrimSpace(d), strings.TrimSpace(t)
}

// Clear removes the record on a CLEAN shutdown.
//
// It is not what makes the answer correct — a killed agent never reaches this, which is exactly why Resolve
// pairs the value with the SCM rather than trusting the value's existence. Clearing is still worth doing: it
// keeps a stopped-by-an-operator box from carrying a version string that reads as current to anything that
// looks at the registry directly.
func Clear() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, KeyPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.DeleteValue(ValueRunningVersion)
	_ = k.DeleteValue(ValueRunningPID)
	_ = k.DeleteValue(ValueRunningSince)
}

// ServiceName is the agent service whose liveness makes a recorded version a running one.
const ServiceName = "DsseSteer"

// Live asks the SCM whether the agent is running, and is the other argument Resolve needs.
//
// It lives here rather than in the updater because it is not a lookup, it is a DEFINITION: "what counts as
// running" is a decision, and the watchdog already makes a different one for its own purposes (it treats
// START_PENDING as running, so it does not recover an agent that is merely starting). Two callers with two
// hand-written copies of that decision would drift, and the symptom would be a wrong verdict about whether a
// device may execute privileged code — so the two answers are distinguished here, once, and Resolve consumes
// the distinction.
//
// Every failure yields Known=false rather than a guess. A service manager that cannot be opened, or a service
// that cannot be found, is a fault; reporting it as "not running" would silently skip a device from a rollout
// while naming the device as the reason.
func Live() Liveness {
	m, err := mgr.Connect()
	if err != nil {
		return Liveness{}
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		// Includes "the service does not exist", which is genuinely unknown territory for this package: an
		// endpoint with no DsseSteer at all is not one whose running version we can reason about.
		return Liveness{}
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return Liveness{}
	}
	switch st.State {
	case svc.StartPending:
		return Liveness{Known: true, Starting: true}
	case svc.Running:
		return Liveness{Known: true, Running: true}
	default:
		// Stopped, StopPending, Paused and friends all mean the same thing to this package: nothing is executing
		// that we may attribute a version to. StopPending in particular must NOT read as running — an agent on
		// its way down may still have its marker in place, and that marker is the memory Resolve exists to
		// refuse.
		return Liveness{Known: true}
	}
}

// Read returns what is stored, with no interpretation. Pass it to Resolve together with a Liveness — the raw
// record is not an answer and this function deliberately cannot produce one.
func Read() Record {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, KeyPath, registry.QUERY_VALUE)
	if err != nil {
		return Record{}
	}
	defer k.Close()
	v, _, verr := k.GetStringValue(ValueRunningVersion)
	if verr != nil {
		return Record{}
	}
	rec := Record{Version: v, Present: true}
	if pid, _, err := k.GetIntegerValue(ValueRunningPID); err == nil {
		rec.PID = uint32(pid)
	}
	if since, _, err := k.GetStringValue(ValueRunningSince); err == nil {
		rec.Since = since
	}
	return rec
}
