//go:build windows

package winbin

// service_stderr_windows.go -- making a service's own death readable.
//
// ★★★ MEASURED ON win-dev-1, 2026-08-31. The steering agent enrolled, selected its region, wrote its last
// ordinary line, and the process was gone a second later. No stop request, no error, no final line. The box
// stayed dark -- the WFP driver keeps redirecting when the agent dies, by design -- and nothing on disk said
// why.
//
// All three Windows services redirected their output by ASSIGNING os.Stdout and os.Stderr. That captures
// everything the program prints and nothing the RUNTIME prints: a Go panic writes to the process's stderr
// HANDLE, not to the os.Stderr variable. Under the SCM that handle goes nowhere. So the one class of failure
// that kills a service outright was the one class it could not report.
//
// ★ A PIPE CANNOT FIX IT, even with the handle pointed at the pipe: the runtime writes and the process
// exits, and the goroutine draining the pipe lives in that same process, so the tail is lost exactly when it
// matters most. The handle has to point at the FILE.
//
// ★ IT LIVES HERE, NOT IN THREE COPIES. The defect existed in three services and was fixed in one, because
// three files carried the same six lines and only one of them was being edited that day. The fourth service
// gets this for free.
//
// ★ AND THE WATCHDOG IS THE ONE THAT MATTERS MOST. It exists to notice that the agent has died. A watchdog
// that dies silently means nobody notices anything -- the same silence, one level up, where there is no
// remaining layer to catch it.

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// PointStderrHandleAtFile makes the PROCESS's stderr handle refer to f, so a runtime panic lands in the log
// file rather than in the void a service's stderr normally is.
//
// Callers should also set the os.Stderr VARIABLE to the same file: the two are separate, which is the whole
// reason this function exists. Stderr then loses the timestamp prefix a pipe would add, and that is the right
// trade -- a panic without a timestamp can be diagnosed, a panic that was never written cannot.
//
// Best-effort by design: a service that cannot redirect its stderr must still start. It says so in the file
// it CAN write, so the absence of panic output later is explained rather than mysterious.
func PointStderrHandleAtFile(f *os.File) {
	if f == nil {
		return
	}
	if err := windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd())); err != nil {
		fmt.Fprintf(f, "%s log: could not point the OS stderr handle at this file (%v) — a runtime panic will "+
			"not be recorded\n", time.Now().Format("2006-01-02 15:04:05.000"), err)
	}
}
