//go:build windows

// service_windows.go — run the steering agent as a Windows Service (SCM-managed: auto-start at boot,
// service-recovery restart, clean SCM stop). Raw advapi32 syscall (no new module dependency, consistent with
// procbypass/authverify/quicblock). The service hosts the same steer-all redirect logic; on SERVICE_CONTROL_STOP
// it closes the capture for a CLEAN shutdown (so deferred cleanup — QUIC block, inbound policy — runs).
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/runstate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/winbin"
)

// logServiceExit is the agent's last words, and it says them where somebody will find them.
//
// Two sinks, for the same reason the watchdog has two: the rolling file beside the binary answers "what
// happened on this box", and it is where the story already is — `dsse-steer.log` had heartbeats every 15
// seconds right up to the end. The event log answers "did something happen to this fleet" for whatever
// collects Windows events, and it is what the file cannot do: on 2026-08-13 this agent's log simply STOPPED
// mid-sentence, and nothing outside the box could tell that from a machine that had been switched off.
//
// The source is registered here rather than only at install, because the boxes that need this most are the
// ones already installed by an MSI that never registered it — DsseSteer was not a registered source on
// win-dev-1, so even its errors would have landed as "the description cannot be found".
func logServiceExit(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	l, err := eventlog.Open(serviceName)
	if err != nil {
		_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Info|eventlog.Warning|eventlog.Error)
		if l, err = eventlog.Open(serviceName); err != nil {
			return // best-effort: the file sink above already has it
		}
	}
	defer l.Close()
	_ = l.Error(1, msg)
}

const serviceName = "DsseSteer"

// wfpDriverServiceName is the kernel callout-driver service that exposes the control device
// \\.\DsseWfp. With --backend wfp the steer agent is useless without it, so we declare a service
// dependency at install time (see installService).
const wfpDriverServiceName = "DsseWfp"

var advapi32 = syscall.NewLazyDLL("advapi32.dll")
var (
	procStartServiceCtrlDispatcherW   = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerExW = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus              = advapi32.NewProc("SetServiceStatus")
)

const (
	svcWin32OwnProcess = 0x00000010
	svcStopped         = 1
	svcStartPending    = 2
	svcStopPending     = 3
	svcRunning         = 4
	svcAcceptStop      = 0x00000001
	svcAcceptShutdown  = 0x00000004
	svcControlStop     = 0x00000001
	svcControlShutdown = 0x00000005
)

type svcStatusT struct {
	serviceType             uint32
	currentState            uint32
	controlsAccepted        uint32
	win32ExitCode           uint32
	serviceSpecificExitCode uint32
	checkPoint              uint32
	waitHint                uint32
}

type svcTableEntry struct {
	name *uint16
	proc uintptr
}

var (
	svcStatusHandle uintptr
	svcStopCh       chan struct{}
	svcWorkFn       func(stop <-chan struct{}) error
	svcStopOnce     sync.Once
	// svcWorkDone closes when the work loop returns, so the stop path can tell "still shutting down" from
	// "never going to".
	svcWorkDone = make(chan struct{})
)

func setSvcState(state, accepts, waitHint uint32) {
	s := svcStatusT{serviceType: svcWin32OwnProcess, currentState: state, controlsAccepted: accepts, waitHint: waitHint}
	procSetServiceStatus.Call(svcStatusHandle, uintptr(unsafe.Pointer(&s)))
}

// setSvcStopped reports the STOP, and reports whether the agent meant it.
//
// ★ THE AGENT DIED SILENTLY FOR A DAY BECAUSE THIS DID NOT EXIST (2026-08-13, win-dev-1). The work function's
// error was discarded — `_ = svcWorkFn(...)` — so an agent that gave up after two minutes and an operator who
// typed `sc stop` produced the SAME observable: state Stopped, WIN32_EXIT_CODE 0, and not one line anywhere.
// Measured on the box: DsseSteer exited ~2m15s after every start, the device went dark in the Console, and the
// only reason the disappearance was noticed at all is that a human looked at the device list and asked.
//
// serviceSpecificExitCode with ERROR_SERVICE_SPECIFIC_ERROR is how a Windows service says "I stopped because
// something went wrong" — SCM records it, `sc queryex` shows it, and the failure actions configured for the
// service (restart, run a command) can finally fire, none of which a clean 0 will ever trigger.
func setSvcStopped(err error) {
	s := svcStatusT{serviceType: svcWin32OwnProcess, currentState: svcStopped}
	if err != nil {
		const errorServiceSpecificError = 1066
		s.win32ExitCode = errorServiceSpecificError
		s.serviceSpecificExitCode = 1
	}
	procSetServiceStatus.Call(svcStatusHandle, uintptr(unsafe.Pointer(&s)))
}

func svcCtrlHandler(ctrl, _, _, _ uintptr) uintptr {
	switch uint32(ctrl) {
	case svcControlStop, svcControlShutdown:
		setSvcState(svcStopPending, 0, 8000)
		// ★ SAY THAT THE STOP ARRIVED (2026-08-14). A stop that hangs is indistinguishable from a stop that was
		// never delivered, and on this box the difference decided where to look: the SCM reported StopPending
		// while the agent kept steering traffic and kept its redirect listener open for minutes. Printed here,
		// at the one place that learns of it first, so the log says how far the request got.
		fmt.Println("steer: SCM stop received — asking the capture to close")
		svcStopOnce.Do(func() { close(svcStopCh) })

		// A stop that does not complete is a fault, not patience. The agent holds the redirect listener and the
		// WFP policy until the capture closes, so an endpoint stuck here is still steering every connection on
		// the box through an agent the operator believes is shutting down.
		go func() {
			select {
			case <-svcWorkDone:
			case <-time.After(20 * time.Second):
				logServiceExit("dsse-steer: STOP REQUESTED 20s ago and the work loop has not returned. This " +
					"endpoint is still steering — the redirect listener and the WFP policy are still in force — " +
					"while the service reports StopPending. Recover with: dsse-steer.exe --mode recover")
			}
		}()
	}
	return 0 // NO_ERROR
}

func svcMain(_ uint32, _ **uint16) uintptr {
	name, _ := syscall.UTF16PtrFromString(serviceName)
	h, _, _ := procRegisterServiceCtrlHandlerExW.Call(uintptr(unsafe.Pointer(name)), syscall.NewCallback(svcCtrlHandler), 0)
	svcStatusHandle = h
	setSvcState(svcStartPending, 0, 12000)
	setSvcState(svcRunning, svcAcceptStop|svcAcceptShutdown, 0)

	// Record what is RUNNING, from the running process, before any work starts. A second process (DsseUpdater)
	// has no other way to learn it: agentVersion() is unexported in this command's package main, and the on-disk
	// binary answers a different question — on the box that matters, the one holding new bytes and running old
	// code, the file's answer is the wrong one. Written here rather than in the work function because this is
	// the one place with a matching clean exit.
	runstate.Write(agentVersion())
	fmt.Printf("steer: running version %s recorded for the updater (%s)\n", agentVersion(), runstate.KeyPath)

	// blocks until the work returns (on SCM stop the stop ch is closed)
	//
	// ★ THE ERROR IS NOT DISCARDED ANY MORE. It was `_ =`, and that is how this agent could stop enforcing and
	// leave nothing to find — see setSvcStopped. Reported before runstate.Clear(), so the last thing written is
	// why, not the tidying up.
	workErr := svcWorkFn(svcStopCh)
	close(svcWorkDone)
	stopWasRequested := false
	select {
	case <-svcStopCh:
		stopWasRequested = true
	default:
	}
	switch {
	case workErr != nil:
		logServiceExit(fmt.Sprintf("dsse-steer: the agent STOPPED because its work returned an error: %v. "+
			"This endpoint is no longer steering and no longer reporting; nothing else on the box will say so.",
			workErr))
	case !stopWasRequested:
		// No error and nobody asked it to stop, yet here it is. That is not a clean shutdown, it is the agent
		// deciding on its own to stop enforcing, and it deserves the same volume as a crash.
		workErr = fmt.Errorf("the work loop returned with no error and no stop request")
		logServiceExit("dsse-steer: the agent STOPPED without being asked and without reporting a reason — the " +
			"work loop simply returned. This endpoint is no longer steering; treat it as a fault, not a shutdown.")
	default:
		fmt.Println("dsse-steer: stopping on an SCM stop request")
	}

	// Clean shutdown only. A killed agent never reaches this, which is precisely why the value alone is not the
	// answer: runstate.Resolve pairs it with the SCM's view of this service rather than trusting that it exists.
	runstate.Clear()
	setSvcStopped(workErr)
	return 0
}

// runAsService connects to the SCM and runs work() under service control. Blocks for the service lifetime.
func runAsService(work func(stop <-chan struct{}) error) error {
	svcStopCh = make(chan struct{})
	svcWorkFn = work
	name, _ := syscall.UTF16PtrFromString(serviceName)
	table := []svcTableEntry{{name: name, proc: syscall.NewCallback(svcMain)}, {name: nil, proc: 0}}
	r, _, e := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if r == 0 {
		return fmt.Errorf("StartServiceCtrlDispatcher (is this running under the SCM? use --service-install): %v", e)
	}
	return nil
}

// installService registers the service to run `exe --service-run <args>` at boot, with restart-on-failure
// recovery. Uses sc.exe (note the required space after each `key=`).
func installService(exePath string, args []string) error {
	bin := `"` + exePath + `" --service-run ` + strings.Join(args, " ")
	createArgs := []string{"create", serviceName, "binPath=", bin, "start=", "auto"}
	if wfpBackendRequested(args) {
		// The WFP backend can't steer without the kernel callout driver loaded (control device
		// \\.\DsseWfp). Declaring the dependency makes the SCM start DsseWfp before this service — even
		// though the driver is DEMAND_START — so a reboot can't leave the auto-start steer agent running
		// against an absent driver (the exact broken state this guards against).
		createArgs = append(createArgs, "depend=", wfpDriverServiceName)
	}
	createArgs = append(createArgs, "DisplayName=", "Dsse Steering Agent")
	// From the system directory, never %PATH% — see package winbin. This registers a SYSTEM service; what gets
	// to do that must not be decided by search order.
	sc, err := winbin.System("sc.exe")
	if err != nil {
		return err
	}
	if out, err := exec.Command(sc, createArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("sc create: %v: %s", err, out)
	}
	// recovery: restart after 5s on the 1st/2nd/3rd failure; reset the counter daily.
	_ = exec.Command(sc, "failure", serviceName, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/5000").Run()
	_ = exec.Command(sc, "description", serviceName, "Dsse steer-all transport agent (signed exclusions, QUIC block).").Run()
	return nil
}

// wfpBackendRequested reports whether the baked service args select the WFP callout-driver backend
// (--backend wfp / --backend=wfp), which needs the DsseWfp kernel driver loaded first.
func wfpBackendRequested(args []string) bool {
	for i, a := range args {
		if a == "--backend=wfp" || a == "-backend=wfp" {
			return true
		}
		if (a == "--backend" || a == "-backend") && i+1 < len(args) && args[i+1] == "wfp" {
			return true
		}
	}
	return false
}

func uninstallService() error {
	sc, err := winbin.System("sc.exe")
	if err != nil {
		return err
	}
	_ = exec.Command(sc, "stop", serviceName).Run()
	if out, err := exec.Command(sc, "delete", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("sc delete: %v: %s", err, out)
	}
	return nil
}
