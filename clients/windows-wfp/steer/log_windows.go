//go:build windows

// log_windows.go — when running under the SCM (no console), the agent's fmt.Printf/Println diagnostics would go
// nowhere, making field problems (e.g. a Wi-Fi<->wired switch that breaks steering) undiagnosable. This points
// stdout/stderr at a rolling, TIMESTAMPED log file next to the binary so the steer/fail-open/reconcile decisions
// (and their timing relative to a network switch) are on disk.
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/winbin"
)

// redirectServiceLogs sends stdout+stderr through a timestamping pipe to outputs/windows/dsse-steer.log
// (truncating if it has grown past a few MB so it can't fill the disk). Every line is prefixed with a
// millisecond timestamp so a live network switch can be correlated with the agent's reaction. Best-effort: on
// any failure it falls back to a plain (untimestamped) file or leaves stdout untouched. Returns the log path.
func redirectServiceLogs() string {
	path := logFilePath()
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if fi, err := os.Stat(path); err == nil && fi.Size() > 8*1024*1024 {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return ""
	}
	// Pipe stdout/stderr through a goroutine that stamps each line with the time. os.Stdout must be an *os.File,
	// so we use the pipe's write end and read from the other side.
	// ★★★ THE OS-LEVEL STDERR HANDLE POINTS AT THE FILE, NOT AT THE PIPE (2026-08-31).
	//
	// A Go runtime panic does NOT write to the os.Stderr VARIABLE — it writes to the process's stderr HANDLE.
	// Assigning os.Stderr therefore captures everything this code prints and nothing the runtime prints, so a
	// service that panics leaves no trace at all: for a service, the real stderr goes nowhere.
	//
	// Measured on win-dev-1: the agent enrolled, selected its region, logged its last ordinary line, and the
	// process was gone a second later. No stop request, no error, no final line. The box stayed dark — the
	// driver keeps redirecting when the agent dies, by design — and there was nothing on disk to say why.
	//
	// The pipe cannot fix this even with SetStdHandle pointed at it: the runtime writes and the process
	// exits, and the goroutine draining the pipe lives in that same process, so the tail is lost exactly when
	// it matters most.
	//
	// So stderr goes STRAIGHT TO THE FILE and gives up its timestamp prefix. That is the right trade — a
	// panic without a timestamp can be diagnosed, a panic that was never written cannot. Stdout keeps the
	// pipe, because that is the running commentary a network switch has to be correlated against.
	winbin.PointStderrHandleAtFile(f)
	r, w, perr := os.Pipe()
	if perr != nil {
		os.Stdout, os.Stderr = f, f // fall back to untimestamped direct file
		log.SetOutput(f)
	} else {
		os.Stdout, os.Stderr = w, f
		log.SetOutput(w)
		go func() {
			sc := bufio.NewScanner(r)
			sc.Buffer(make([]byte, 64*1024), 1<<20)
			for sc.Scan() {
				fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05.000"), sc.Text())
			}
		}()
	}
	fmt.Printf("===== dsse-steer service start =====")
	return path
}

func logFilePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "dsse-steer.log"
	}
	return filepath.Join(filepath.Dir(exe), "dsse-steer.log")
}
