//go:build windows

// capture_wfp_procnotify_windows.go — userspace end of the driver's process-creation notification.
//
// Signature-form steer exclusions (signed:/publisher:/subject:/thumbprint:) cannot be evaluated in-kernel, so
// userspace verifies the signer and pushes exact NT image paths into the driver's bypass table. Discovery used
// to be a thirty-second scan of RUNNING processes, which a five-second process is never present for — that is
// how `signed:winget.exe` came to be distributed, verified, self-reported as effective, and enforce nothing
// (measured 2026-08-06). The driver is the only component that learns of a process at the instant it is
// created, so this channel is where the gap actually closes.
//
// It is a LONG POLL, not a drain-poll: the IOCTL blocks in the driver until a process appears or the driver's
// own timeout expires. There is no scan interval to miss a process inside of.
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ioctlWFPWaitProcEvents blocks in the driver until at least one process-creation event is queued (or the
// driver times out and returns zero). Output layout: [uint32 count][uint32 dropped][wfpProcEvent x count].
var ioctlWFPWaitProcEvents = wfpCtlCode(0x807)

// ioctlWFPSetAppVerdict releases a process the driver is holding at creation, once this side has pushed the
// image's verdict into the exact-APP_ID table.
var ioctlWFPSetAppVerdict = wfpCtlCode(0x808)

// procHoldMs is how long the driver may hold a creating process while this side decides. Notification alone
// does not close the race — measured: with a cold store the first flow was still steered, because the
// Authenticode check plus the policy IOCTL do not finish before the process connects. Holding the CREATION
// (not the flow) puts the decision before the process's first instruction. Deliberately small: the cost of
// being wrong is launch latency, and the fallback on timeout is exactly the old behaviour.
const procHoldMs = 60

// wfpProcWaitRequest mirrors DSSE_PROC_WAIT_REQUEST. WaitBlockMs = 0 tells the driver never to hold, which is
// the posture whenever no signature-form rule is active — an ordinary deployment pays nothing per launch.
type wfpProcWaitRequest struct {
	WaitBlockMs uint32
}

// wfpAppVerdict mirrors DSSE_APP_VERDICT.
type wfpAppVerdict struct {
	ProcessID uint32
}

// releaseHeldProcess tells the driver this pid has been decided. Best-effort: if the hold already timed out
// the driver treats it as a no-op, and the app is still discovered from its first steered flow.
func releaseHeldProcess(h syscall.Handle, pid uint32) {
	v := wfpAppVerdict{ProcessID: pid}
	var ret uint32
	_ = syscall.DeviceIoControl(h, ioctlWFPSetAppVerdict,
		(*byte)(unsafe.Pointer(&v)), uint32(unsafe.Sizeof(v)), nil, 0, &ret, nil)
}

// procEventsPerCall is how many events one IOCTL may return. The driver's ring is larger; this only bounds
// the buffer we hand it per call.
const procEventsPerCall = 32

// wfpProcEvent mirrors DSSE_PROC_EVENT in dsse_wfp.h byte-for-byte. ImagePath is the NT device path — the
// same form the kernel compares against ALE_APP_ID, so it can be pushed back verbatim with no conversion.
type wfpProcEvent struct {
	ProcessID uint32
	_pad      uint32
	ImagePath [wfpExactAppLen]uint16
}

// win32PathForProcEvent returns a path Authenticode verification can open. The live process is preferred
// because it yields the ordinary drive-letter path; a process that already exited (the whole point of this
// channel is that they are short-lived) falls back to the NT path via GLOBALROOT, which CreateFile accepts.
// Only the basename and the signature matter to a signature-form rule, so either form matches identically.
func win32PathForProcEvent(pid uint32, ntPath string) string {
	if p, ok := processImagePath(pid); ok && p != "" {
		return p
	}
	if ntPath == "" {
		return ""
	}
	return `\\?\GLOBALROOT` + ntPath
}

// runProcEventWatcher long-polls the driver and reports every created process. It returns when stop closes or
// when the device cannot be opened — the WFP backend cannot run without the driver anyway, and the periodic
// scan plus learn-on-steer remain as backstops, so a failure here degrades discovery rather than breaking it.
// holdMs is re-read on every wait so the hold disappears the moment the last signature-form rule does: an
// exclusion set with no signature rules must not cost a microsecond at process creation.
func runProcEventWatcher(stop <-chan struct{}, holdMs func() uint32, onProcess func(pid uint32, ntPath string, release func())) {
	// Retry rather than give up. A single attempt at startup loses the race against driver readiness on a
	// service start, and stages 1 and 2 would then be OFF for the life of the process, announced once on
	// stderr — the same silence family as the defect this machinery exists to fix. Recovery is logged too,
	// so "it came back" is visible and not just inferred from the absence of complaints.
	var h syscall.Handle
	attempt := 0
	for {
		var err error
		h, err = openWFPDevice()
		if err == nil {
			if attempt > 0 {
				fmt.Printf("steer_capture: process-notify watcher recovered after %d failed open(s)\n", attempt)
			}
			break
		}
		attempt++
		if attempt == 1 || attempt%10 == 0 {
			fmt.Fprintf(os.Stderr, "wfp: process-notify watcher cannot open the driver (attempt %d: %v); signature exclusions run on learn-on-steer until it does\n", attempt, err)
		}
		select {
		case <-stop:
			return
		case <-time.After(3 * time.Second):
		}
	}
	defer syscall.CloseHandle(h)

	// Verdicts MUST go out on their own handle. openWFPDevice opens for SYNCHRONOUS I/O, so the I/O manager
	// serialises every request on one file object — and the wait handle is, by design, parked inside a
	// blocking IOCTL almost all the time. Sharing it means each verdict queues behind the very wait it is
	// supposed to end, so every hold runs to timeout. Measured exactly that: unrelated launches went from
	// 46ms to ~110ms and the cold curl went back to being steered, the moment event handling moved off the
	// watcher's own goroutine and started overlapping the wait.
	hv, err := openWFPDevice()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wfp: process-notify cannot open a verdict handle (%v); holds would run to timeout, so not arming them\n", err)
		return
	}
	defer syscall.CloseHandle(hv)

	const hdr = 8 // count + dropped
	buf := make([]byte, hdr+procEventsPerCall*int(unsafe.Sizeof(wfpProcEvent{})))
	fmt.Printf("steer_capture: process-notify watcher started (signature exclusions now see short-lived processes)\n")

	// Handle events with BOUNDED CONCURRENCY rather than one at a time. Serially, a single slow Authenticode
	// check makes every other held creation in the batch burn its full timeout. `signed:` rules short-circuit
	// on basename before any crypto — which is why unrelated launches measured clean — but publisher:,
	// subject: and thumbprint: have no cheap pre-filter, so under one of those EVERY first-seen image on the
	// machine verifies inside the hold window. A saturated pool releases immediately instead of queueing: a
	// launch must never wait on our backlog.
	const procWorkers = 4
	work := make(chan func(), procEventsPerCall)
	for i := 0; i < procWorkers; i++ {
		go func() {
			for job := range work {
				job()
			}
		}()
	}
	defer close(work)

	for {
		select {
		case <-stop:
			return
		default:
		}
		var ret uint32
		req := wfpProcWaitRequest{WaitBlockMs: holdMs()}
		err := syscall.DeviceIoControl(h, ioctlWFPWaitProcEvents,
			(*byte)(unsafe.Pointer(&req)), uint32(unsafe.Sizeof(req)),
			&buf[0], uint32(len(buf)), &ret, nil)
		if err != nil {
			// The driver may have been stopped underneath us. Do not spin.
			fmt.Fprintf(os.Stderr, "wfp: process-notify wait failed: %v\n", err)
			select {
			case <-stop:
			case <-time.After(2 * time.Second):
			}
			continue
		}
		if ret < hdr {
			continue
		}
		count := *(*uint32)(unsafe.Pointer(&buf[0]))
		dropped := *(*uint32)(unsafe.Pointer(&buf[4]))
		if dropped > 0 {
			// Fail loud. A dropped event costs one steered flow (learn-on-steer still catches the app) and can
			// never cause a wrong bypass — but a channel that loses events quietly is exactly how the original
			// defect stayed invisible, so it is said out loud.
			fmt.Fprintf(os.Stderr, "wfp: process-notify dropped %d event(s) (ring overflow); those apps are discovered from their first steered flow instead\n", dropped)
		}
		for i := uint32(0); i < count && int(hdr)+int(i+1)*int(unsafe.Sizeof(wfpProcEvent{})) <= int(ret); i++ {
			e := (*wfpProcEvent)(unsafe.Pointer(&buf[hdr+int(i)*int(unsafe.Sizeof(wfpProcEvent{}))]))
			nt := strings.TrimRight(syscall.UTF16ToString(e.ImagePath[:]), "\x00")
			pid := e.ProcessID
			release := func() { releaseHeldProcess(hv, pid) }
			if nt == "" {
				release() // nothing to decide; do not make the launch wait out the timeout
				continue
			}
			job := func() { onProcess(pid, nt, release) }
			select {
			case work <- job:
			default:
				release() // pool saturated: let it launch and let learn-on-steer catch it
			}
		}
	}
}
