//go:build windows

// main_windows.go — the Windows half of dsse-watchdog: read the driver and the service manager, hand the
// result to Decide (decide.go), and run the network panic button when told to.
//
//	dsse-watchdog --service-install        register DsseWatchdog (LocalSystem, auto-start)
//	dsse-watchdog --service-uninstall
//	dsse-watchdog --service-run            run under the SCM
//	dsse-watchdog --once                   one tick, print the decision, do NOT act (safe to run by hand)
//	dsse-watchdog --once --act             one tick, act on it
//	dsse-watchdog --event-selftest         write probe events and print how to read them back (see log_windows.go)
//
// Everything policy-shaped lives in decide.go and is tested off-Windows. What is here is the plumbing that
// cannot be: DeviceIoControl, the SCM, and launching dsse-steer.
package main

import (
	"flag"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/wfpstate"
)

const (
	// IOCTL_DSSE_GET_STATS: CTL_CODE(FILE_DEVICE_NETWORK=0x12, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS).
	ioctlDsseWFPGetStats = (0x12 << 16) | (0x802 << 2)

	serviceName      = "DsseWatchdog"
	steerServiceName = "DsseSteer"
	wfpDevicePath    = `\\.\DsseWfp`
)

// steerExeFallbackNames are tried, in order, beside the watchdog when the DsseSteer service cannot name its own
// binary. `dsse-steer.exe` is what the MSI installs; `steer.exe` is what a hand-deployed box has, and win-dev-1
// — the reference steering fixture — is one of those.
var steerExeFallbackNames = []string{"dsse-steer.exe", "steer.exe"}

var (
	buildVersion = "0.0.0-dev"
	buildCommit  = "unknown"
)

func main() {
	serviceInstall := flag.Bool("service-install", false, "register DsseWatchdog (LocalSystem, auto-start)")
	serviceUninstall := flag.Bool("service-uninstall", false, "stop + remove DsseWatchdog")
	serviceRun := flag.Bool("service-run", false, "run under the Windows service control manager")
	once := flag.Bool("once", false, "evaluate once, print the decision, and exit")
	eventSelfTest := flag.Bool("event-selftest", false, "write one probe event at each candidate event ID and print how to read them back; used to settle which IDs the registered message file can actually render")
	act := flag.Bool("act", false, "with --once: actually perform the decided action (default is dry-run)")
	interval := flag.Duration("interval", 15*time.Second, "how often to evaluate")
	maxRecoveries := flag.Int("max-recoveries", 3, "recoveries allowed per --recovery-window before the watchdog reports instead of acting (0 = unlimited)")
	recoveryWindow := flag.Duration("recovery-window", time.Hour, "rolling window for --max-recoveries")
	flag.Parse()

	switch {
	case *serviceInstall:
		if err := installService(); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-watchdog: install: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("dsse-watchdog: %s installed (LocalSystem, auto-start)\n", serviceName)
	case *serviceUninstall:
		if err := uninstallService(); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-watchdog: uninstall: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("dsse-watchdog: %s removed\n", serviceName)
	case *serviceRun:
		// Under the SCM there is no console: without this the entire record of what this process did is
		// discarded, which is what win-dev-1 found.
		if p := redirectServiceLogs(); p != "" {
			fmt.Printf("===== dsse-watchdog service start version=%s+%s log=%s =====\n", buildVersion, buildCommit, p)
		}
		if err := svc.Run(serviceName, &watchdogService{
			interval: *interval,
			state:    newWatchState(*maxRecoveries, *recoveryWindow),
		}); err != nil {
			fmt.Fprintf(os.Stderr, "dsse-watchdog: service: %v\n", err)
			os.Exit(1)
		}
	case *eventSelfTest:
		evt := openEventLog()
		defer evt.close()
		runEventSelfTest(evt)
	case *once:
		// Interactive: output goes to the console the operator is looking at, and events still go to the log so
		// a hand-run recovery is as visible as an unattended one.
		evt := openEventLog()
		defer evt.close()
		newWatchState(*maxRecoveries, *recoveryWindow).tick(*act, evt)
	default:
		fmt.Fprintln(os.Stderr, "dsse-watchdog: one of --service-install / --service-uninstall / --service-run / --once / --event-selftest is required")
		os.Exit(2)
	}
}

// watchState is what survives between ticks. Both fields exist to stop this process being noisy in a way that
// makes it useless: the limiter bounds how often it tears steering down, and the throttle bounds how often it
// says the same thing to the event log.
type watchState struct {
	limiter *RecoveryLimiter
	events  *EventThrottle
}

func newWatchState(maxRecoveries int, window time.Duration) *watchState {
	return &watchState{
		limiter: &RecoveryLimiter{Max: maxRecoveries, Window: window},
		// One hour: long enough that a stuck box does not bury the log, short enough that a condition lasting a
		// working day is still visible to a collector that only keeps a rolling window.
		events: &EventThrottle{ReassertAfter: time.Hour},
	}
}

// tick is one evaluation. Kept small and side-effect-visible: everything it decides is printed, whether or
// not it acts, so `--once` without `--act` is a truthful preview of what the service would have done.
func (w *watchState) tick(act bool, evt *eventWriter) {
	obs := observe()
	d := Decide(obs)

	// ALWAYS write the decision to the FILE, including ActionNone. A watchdog that only speaks when it acts
	// gives an operator no way to tell "watching, all well" from "not running at all", and those need different
	// responses. The event log gets only the reportable moments (below), or the handful that matter would be
	// buried under one entry every 15 seconds.
	// agent_should_run is here for the same reason every other field is: the decision must be re-derivable from
	// the line. Without it, the difference between "stopped on purpose" and "stopped and this box is supposed to
	// be steering" is invisible in the log, and that difference is the whole of the 2026-08-14 finding.
	line := fmt.Sprintf("dsse-watchdog: version=%s+%s decision=%s driver_present=%t driver_state_known=%t armed=%t "+
		"observe_only=%t owner_present=%t agent_running=%t agent_state_known=%t agent_should_run=%t "+
		"agent_start_type_known=%t dns_residue=%t dns_residue_known=%t recovery_tool=%q reason=%q",
		buildVersion, buildCommit, d.Action, obs.DriverPresent, obs.DriverStateKnown, obs.DriverArmed,
		obs.DriverObserveOnly, obs.DriverOwnerPresent, obs.AgentRunning, obs.AgentStateKnown,
		obs.AgentShouldBeRunning, obs.AgentStartTypeKnown,
		obs.DNSTakeoverResidue, obs.DNSResidueKnown, obs.RecoveryToolPath, d.Reason)
	fmt.Println(line)

	// Say it on EVERY tick, not only when recovery is needed. A watchdog that cannot run recovery is useless
	// on this box, and the point of resolving the binary up front is that the operator learns it during a
	// quiet minute rather than during the outage.
	if obs.RecoveryToolPath == "" {
		fmt.Printf("dsse-watchdog: WARNING recovery is NOT possible on this box: %s\n", obs.RecoveryToolErr)
	}

	// Standing conditions go to the event log through the throttle. Unlike `recover`, which changes the state
	// and so cannot repeat indefinitely, these two persist tick after tick from one unchanged cause — 240 events
	// an hour on win-dev-1, burying the IDs a collector is supposed to match on.
	standing := ""
	if d.Action == ActionReportOnly || d.Action == ActionCannotRecover {
		standing = d.Action.String() + "|" + d.Reason
	}
	emit, cleared := w.events.Observe(standing, time.Now())
	if cleared != "" {
		// A collector that saw the alert and never sees the resolution has to keep assuming the box is broken.
		msg := fmt.Sprintf("dsse-watchdog: the condition previously reported has CLEARED (was: %s). Current state: %s",
			cleared, d.Reason)
		fmt.Println(msg)
		evt.info(evtCleared, msg)
	}

	if d.Action == ActionCannotRecover {
		// Not report_only. This box needs someone, and that has to be visible to whatever collects events.
		if emit {
			evt.err(evtCannotRecover, line)
		}
		return
	}

	if d.Action == ActionReportOnly {
		// Report-only means something is wrong that this process must not touch. If that never reaches the
		// event log, the only component that noticed has told nobody.
		if emit {
			evt.warn(evtReportOnly, line)
		}
		return
	}
	if d.Action != ActionRecover {
		return
	}
	if !act {
		fmt.Println("dsse-watchdog: --act not given; NOT running recovery (dry run)")
		return
	}
	if ok, why := w.limiter.Allow(time.Now()); !ok {
		// The moment an operator most needs the explanation, and the moment it was least visible: on win-dev-1
		// a box sat black-holed for 85 seconds while this sentence went to a discarded stdout.
		msg := "dsse-watchdog: RATE-LIMITED, this box is NOT being recovered: " + why + " | " + d.Reason
		fmt.Println(msg)
		evt.err(evtRateLimited, msg)
		return
	}
	if err := runSteerRecover(obs.RecoveryToolPath); err != nil {
		msg := fmt.Sprintf("dsse-watchdog: recovery FAILED: %v — this box is still broken. %s", err, d.Reason)
		fmt.Println(msg)
		evt.err(evtRecoverFail, msg)
		return
	}
	// Recovery is not finished because the command exited 0. Re-read: the whole reason this watchdog exists is
	// that a disarm which silently did not happen looks exactly like one that did. Both residues are re-checked,
	// because after the DNS-only case there is no redirect to look at — and the classification distinguishes
	// "armed again with the agent behind it" from "armed with nothing behind it", which the first version could
	// not, so a successful recovery raced by the SCM's restart was filed as an error.
	outcome, detail := ClassifyPostRecovery(observe())
	switch outcome {
	case PostRecoveryStillBroken:
		msg := "dsse-watchdog: recovery ran but the box is STILL broken: " + detail
		fmt.Println(msg)
		evt.err(evtRecoverFail, msg)
	case PostRecoverySteeringResumed:
		// A real incident with a benign ending. Reportable — this box was black-holed seconds ago — but it must
		// not read as either "recovery failed" or "enforcement is off", because neither is true.
		msg := "dsse-watchdog: recovery ran and STEERING RESUMED — " + detail + ". Cause of the incident: " + d.Reason
		fmt.Println(msg)
		evt.warn(evtSteeringResumed, msg)
	default:
		msg := "dsse-watchdog: RECOVERED — this box is on its native network, UNSTEERED. Enforcement is off until " +
			"the agent comes back; this is a reportable event, not a normal state. Cause: " + d.Reason
		fmt.Println(msg)
		evt.warn(evtRecovered, msg)
	}
}

// observe reads the two facts Decide needs. Every failure is recorded as an unknown rather than guessed —
// see the three-state fields on Observation.
func observe() Observation {
	o := Observation{}

	state, present, known := readDriverState()
	o.DriverPresent = present
	o.DriverStateKnown = known
	o.DriverArmed = state.Armed
	o.DriverObserveOnly = state.ObserveOnly
	o.DriverOwnerPresent = state.OwnerPresent

	running, err := serviceRunning(steerServiceName)
	if err != nil {
		o.AgentStateKnown = false
	} else {
		o.AgentStateKnown = true
		o.AgentRunning = running
	}

	// Whether this box EXPECTS the agent to be running. Read separately from the running state because the two
	// fail independently and because a stopped agent means opposite things on a box that starts it
	// automatically and one where an operator disabled it — see Observation.AgentShouldBeRunning.
	auto, aknown := serviceStartsAutomatically(steerServiceName)
	o.AgentShouldBeRunning = auto
	o.AgentStartTypeKnown = aknown

	// Locate the agent ONCE per tick. Two lookups would mean two SCM connects and, worse, two chances to
	// disagree about where the agent is.
	loc := locateAgent()
	o.RecoveryToolPath = loc.RunPath
	if loc.RunErr != nil {
		o.RecoveryToolErr = loc.RunErr.Error()
	}

	// ★ The residue is looked up in the agent's DIRECTORIES, which are known even when no runnable binary is —
	// see AgentStateDirs. Deriving it from the runnable binary made a missing agent blind the residue check,
	// and an unknown residue degrades the decision to report_only, so `cannot_recover` could not be reached in
	// the exact state it names.
	residue, rknown := dnsTakeoverResidue(loc.Dirs)
	o.DNSTakeoverResidue = residue
	o.DNSResidueKnown = rknown
	return o
}

// dnsResidueFileName is the agent's persisted pre-takeover resolver snapshot. Must match
// resolverBackupPath() in steer/dns_resolver_windows.go — the agent writes it beside its own binary when it
// points the resolver at itself, and deletes it once it has put the servers back.
const dnsResidueFileName = "dsse_dns_resolver_backup.json"

// dnsTakeoverResidue reports (residue, known): whether the agent left the resolver pointed at its dead
// loopback proxy.
//
// The FILE is the signal, not "the resolver is on loopback". It is DSSE's own record of an unfinished change,
// so it cannot be confused with a box legitimately running a local resolver, and it is the same evidence
// --mode recover consumes to restore the servers.
//
// It lives beside the AGENT, so every directory the agent is known to have occupied is searched. Crucially
// that list does NOT require the agent binary to still be there: an install directory is a place, and asking
// "is there a file here" needs nothing runnable. Coupling the two cost win-dev-1 a diagnosis — a renamed agent
// reported dns_residue_known=false on a genuinely orphaned box, so the decision degraded to report_only and
// `cannot_recover` never fired.
func dnsTakeoverResidue(dirs []string) (bool, bool) {
	if len(dirs) == 0 {
		return false, false
	}
	answered := false
	for _, dir := range dirs {
		path := filepath.Join(dir, dnsResidueFileName)
		switch _, serr := os.Stat(path); {
		case serr == nil:
			return true, true
		case os.IsNotExist(serr):
			// A definite absence, including when the directory itself is gone: DSSE state cannot be in a place
			// that does not exist.
			answered = true
		default:
			// Present-but-unreadable is NOT "absent". Reporting it as absent is how a real residue becomes a
			// confident "nothing to do".
			fmt.Printf("dsse-watchdog: could not check the DNS takeover residue at %s: %v\n", path, serr)
		}
	}
	return false, answered
}

// --- driver ---------------------------------------------------------------------------------------------

// readDriverState returns (state, present, known). "present" is false when the device does not exist, which
// is a definite answer meaning "no callout driver, no redirect". "known" is false when the device is there
// but would not answer — a genuine unknown, and the two must not collapse into one another.
//
// The decoding itself lives in the shared wfpstate package, so this watchdog and the steer agent cannot come
// to different conclusions about the same bytes.
func readDriverState() (wfpstate.State, bool, bool) {
	p, err := windows.UTF16PtrFromString(wfpDevicePath)
	if err != nil {
		return wfpstate.State{}, false, false
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
			return wfpstate.State{}, false, true
		}
		return wfpstate.State{}, true, false
	}
	defer windows.CloseHandle(h)

	// Oversized on purpose: an output buffer smaller than the driver's struct returns STATUS_BUFFER_TOO_SMALL,
	// so a tight fit would blind this watchdog the next time a field is appended to DSSE_STATS.
	var buf [256]byte
	var ret uint32
	if err := windows.DeviceIoControl(h, ioctlDsseWFPGetStats, nil, 0, &buf[0], uint32(len(buf)), &ret, nil); err != nil {
		return wfpstate.State{}, true, false
	}
	// A driver too old for the state block cannot say whether it is redirecting; Parse reports that as an
	// error, and an error here is an UNKNOWN, never "not armed".
	st, perr := wfpstate.Parse(buf[:ret])
	if perr != nil {
		return wfpstate.State{}, true, false
	}
	return st, true, true
}

// --- service manager ------------------------------------------------------------------------------------

func serviceRunning(name string) (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		// An ABSENT service is a definite answer: it is not running. Only a failure to ASK is an unknown.
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return false, nil
		}
		return false, err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return false, err
	}
	return st.State == svc.Running || st.State == svc.StartPending, nil
}

// serviceStartsAutomatically reports whether the service is configured to start on its own, and whether that
// could be established at all.
//
// An ABSENT service answers (false, true): a service that does not exist is definitely not configured to start,
// which is a fact rather than an unknown — the same distinction serviceRunning makes, and for the same reason.
// Only a failure to ASK is an unknown, and an unknown here must not turn a deliberately stopped agent into an
// alarm.
//
// DelayedAutoStart counts as automatic: the box still intends to run it, just later.
func serviceStartsAutomatically(name string) (bool, bool) {
	m, err := mgr.Connect()
	if err != nil {
		return false, false
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return false, true
		}
		return false, false
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return false, false
	}
	return cfg.StartType == mgr.StartAutomatic, true
}

// agentLocation separates the two questions this process needs answered about the steering agent, because
// they have different answers and conflating them hid a real outage.
//
//   - RunPath / RunErr: WHAT CAN I EXECUTE to recover this box. Requires a binary that is actually there.
//   - Dirs: WHERE DID THE AGENT LIVE, so its leftover state can be read. Requires only a path, and the service
//     ImagePath still names one when the binary behind it has been renamed, moved or deleted.
type agentLocation struct {
	RunPath string
	RunErr  error
	Dirs    []string
}

// locateAgent answers both questions in one pass.
//
// The SCM is asked FIRST and is authoritative: the service the watchdog already queries for liveness also
// records the exact image it starts, so there is no guessing and no second source of truth to drift. The
// beside-the-watchdog names are a fallback for the case the service is absent entirely — a box where the agent
// was removed but the driver is still armed is precisely one worth recovering.
//
// Every candidate tried is named in RunErr. When recovery is impossible the box is refusing every connection,
// and "not found" without saying where it looked costs the operator the one thing they do not have: time.
func locateAgent() agentLocation {
	loc := agentLocation{}
	var tried []string

	serviceExe := ""
	if p, err := steerExeFromService(); err != nil {
		tried = append(tried, fmt.Sprintf("the %s service ImagePath (unreadable: %v)", steerServiceName, err))
	} else if p == "" {
		tried = append(tried, fmt.Sprintf("the %s service ImagePath (empty)", steerServiceName))
	} else {
		serviceExe = p
		tried = append(tried, fmt.Sprintf("%s (from the %s service ImagePath)", p, steerServiceName))
		if _, err := os.Stat(p); err == nil {
			loc.RunPath = p
		}
	}

	ownExe, oerr := os.Executable()
	// The directory list is built from the ImagePath even when nothing runnable was found there. That is the
	// whole point of the split: a path names a place whether or not a binary is standing on it.
	loc.Dirs = AgentStateDirs(serviceExe, ownExe)

	if loc.RunPath == "" {
		if oerr != nil {
			loc.RunErr = fmt.Errorf("resolve own path: %w", oerr)
			return loc
		}
		dir := filepath.Dir(ownExe)
		for _, name := range steerExeFallbackNames {
			p := filepath.Join(dir, name)
			tried = append(tried, p)
			if _, err := os.Stat(p); err == nil {
				loc.RunPath = p
				break
			}
		}
	}
	if loc.RunPath == "" {
		loc.RunErr = fmt.Errorf("could not find the steering agent binary to run recovery with; tried: %s",
			strings.Join(tried, "; "))
	}
	return loc
}

// steerExeFromService reads the DsseSteer service's configured image path.
func steerExeFromService() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()
	s, err := m.OpenService(steerServiceName)
	if err != nil {
		return "", err
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return "", err
	}
	return ExecutableFromServiceCommandLine(c.BinaryPathName), nil
}

// runSteerRecover invokes the existing network panic button. --recover-keep-services is deliberate: the
// services are not what is broken, the redirect is, and stopping them here would fight whatever is trying to
// bring the agent back.
//
// The binary comes from the observation that decided to recover, rather than being resolved again here. Two
// resolutions could disagree, and the one that mattered — the one the decision was made on — would not be the
// one that ran.
func runSteerRecover(steer string) error {
	if steer == "" {
		return fmt.Errorf("no steering agent binary was resolved for this tick")
	}
	// Bounded: a hung recovery must not wedge the service loop forever. The panic button already bounds its
	// own children, but this process cannot assume that stays true.
	cmd := exec.Command(steer, "--mode", "recover", "--recover-keep-services")
	out := &strings.Builder{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		fmt.Printf("dsse-watchdog: recover output:\n%s\n", out.String())
		return err
	case <-time.After(2 * time.Minute):
		_ = cmd.Process.Kill()
		return fmt.Errorf("recover did not finish within 2 minutes; killed")
	}
}

// --- the service ----------------------------------------------------------------------------------------

type watchdogService struct {
	interval time.Duration
	state    *watchState
}

func (w *watchdogService) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}
	s <- svc.Status{State: svc.Running, Accepts: accepted}

	evt := openEventLog()
	defer evt.close()
	evt.info(evtStarted, fmt.Sprintf("dsse-watchdog started version=%s+%s interval=%s log=%s",
		buildVersion, buildCommit, w.interval, logFilePath()))

	t := time.NewTicker(w.interval)
	defer t.Stop()
	w.state.tick(true, evt)
	for {
		select {
		case <-t.C:
			w.state.tick(true, evt)
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Stopping the watchdog does NOT touch steering. It is an observer; its exit must never be
				// the thing that changes a box's enforcement state.
				s <- svc.Status{State: svc.StopPending}
				return false, 0
			}
		}
	}
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("%s already exists (use --service-uninstall first)", serviceName)
	}
	// Auto-start, and deliberately NOT dependent on DsseSteer or DsseWfp. Depending on either would be exactly
	// backwards: the state this watches for is one of them being absent, and a dependency would stop the
	// watchdog from running precisely then.
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  "Lantern DSSE Network Watchdog",
		Description:  "Restores this device's network if the DSSE steering redirect is left armed with no agent behind it.",
		StartType:    mgr.StartAutomatic,
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		ErrorControl: mgr.ErrorNormal,
	}, "--service-run")
	if err != nil {
		return err
	}
	defer s.Close()
	// Restart on failure: a watchdog that crashed once and stayed down is indistinguishable from one that is
	// watching, and the difference only shows up during the incident it was there for.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}
	// Register the event source here, where we are already elevated. NOT fatal: an unattended recovery still
	// lands in the log file, and refusing to install the watchdog over its reporting channel would trade the
	// thing for the record of the thing.
	if err := installEventSource(); err != nil {
		fmt.Printf("dsse-watchdog: WARNING could not register the %q event source (%v) — recoveries will be in "+
			"%s but NOT in the Windows event log, so nothing that collects events will see them\n",
			eventSource, err, logFilePath())
	}
	return s.Start()
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if st, qerr := s.Query(); qerr == nil && st.State != svc.Stopped {
		if _, cerr := s.Control(svc.Stop); cerr != nil {
			return fmt.Errorf("stop: %w", cerr)
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if st, qerr := s.Query(); qerr == nil && st.State == svc.Stopped {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	removeEventSource() // leaving a registered source behind would make future events unreadable-but-present
	return s.Delete()
}
