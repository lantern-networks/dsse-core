//go:build windows

// log_windows.go — where this updater's output goes.
//
// Same two sinks and the same reasoning as dsse-watchdog: a rolling file beside the binary carrying EVERY
// tick, because "running and nothing published" has to be distinguishable from "not running at all"; and the
// Windows event log carrying only the reportable moments, because one entry per tick would bury them.
//
// ★ ON THE DUPLICATION. This is the third copy of that plumbing (dsse-steer, dsse-watchdog, and now this), and
// it should become one package. It deliberately has not yet: win-dev-1 is mid-verification of the watchdog's
// event behaviour, and moving the file those measurements are read from, while they are being taken, is how a
// verification gets invalidated and then re-run. The extraction is worth one commit after that lands, not
// before.
//
// ★ ON THE RENDERED DESCRIPTION. The measurement came back (win-dev-1, 2026-08-10): EventCreate.exe renders
// 1..1001, so renumbering was the fix and no message-resource DLL is needed. This source moved from 20xx to
// 2xx in the same change as the watchdog's, because settling one and not the other would leave half the
// events wrapped and nobody looking again.
package main

import (
	"bufio"
	"fmt"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/winbin"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc/eventlog"
)

// reportThrottle keeps a standing condition from writing one event per tick.
//
// Same shape and the same reason as the watchdog's EventThrottle, which win-dev-1 found writing 240 events an
// hour from one unchanged cause. It is duplicated rather than shared for the reason in the file comment above.
// The interval is longer here because this service ticks every 30 minutes rather than every 15 seconds, so an
// unchanged condition is already rare; what it prevents is a device stuck for a week filing 336 identical
// errors.
type reportThrottle struct {
	current     string
	announcedAt time.Time
	reassert    time.Duration
}

func newReportThrottle() *reportThrottle { return &reportThrottle{reassert: 24 * time.Hour} }

// should reports whether this condition may be written now, and records it as the standing one.
func (t *reportThrottle) should(condition string) bool {
	now := time.Now()
	if condition != t.current {
		t.current, t.announcedAt = condition, now
		return true
	}
	if t.reassert > 0 && now.Sub(t.announcedAt) >= t.reassert {
		t.announcedAt = now
		return true
	}
	return false
}

// clear reports the condition that has just gone away, if any. A collector that saw the alert and never sees a
// resolution has to keep assuming the device is stuck.
func (t *reportThrottle) clear() string {
	was := t.current
	t.current, t.announcedAt = "", time.Time{}
	return was
}

func logFilePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "dsse-updater.log"
	}
	return filepath.Join(filepath.Dir(exe), "dsse-updater.log")
}

// redirectServiceLogs points stdout/stderr at the rolling file. Best-effort: an updater that refused to run
// because it could not open its log would trade the thing for the record of the thing.
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
	// ★ The OS-level stderr handle must point at the FILE, not at the pipe: a Go panic writes to the process
	// HANDLE, not to the os.Stderr variable, so a service that panics otherwise leaves no trace at all.
	// Measured 2026-08-31, see winbin.PointStderrHandleAtFile.
	winbin.PointStderrHandleAtFile(f)
	r, w, perr := os.Pipe()
	if perr != nil {
		os.Stdout, os.Stderr = f, f
		log.SetOutput(f)
		return path
	}
	os.Stdout, os.Stderr = w, f
	log.SetOutput(w)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05.000"), sc.Text())
		}
	}()
	return path
}

// eventWriter is the event-log half. Nil when the source is not registered; every call is then a no-op,
// because losing the event log is not a reason to stop updating machines.
type eventWriter struct{ l *eventlog.Log }

func openEventLog() *eventWriter {
	l, err := eventlog.Open(eventSource)
	if err != nil {
		return &eventWriter{}
	}
	return &eventWriter{l: l}
}

func (e *eventWriter) close() {
	if e != nil && e.l != nil {
		_ = e.l.Close()
	}
}

func (e *eventWriter) info(id uint32, msg string) { e.write(id, msg, "info") }
func (e *eventWriter) warn(id uint32, msg string) { e.write(id, msg, "warning") }
func (e *eventWriter) err(id uint32, msg string)  { e.write(id, msg, "error") }

func (e *eventWriter) write(id uint32, msg, level string) {
	if e == nil || e.l == nil {
		return
	}
	var werr error
	switch level {
	case "error":
		werr = e.l.Error(id, msg)
	case "warning":
		werr = e.l.Warning(id, msg)
	default:
		werr = e.l.Info(id, msg)
	}
	if werr != nil {
		// Say so in the FILE: an event that failed to be written is itself worth knowing about, and the file is
		// the sink that does not depend on registration.
		fmt.Printf("dsse-updater: could not write event %d to the Windows event log: %v\n", id, werr)
	}
}

func installEventSource() error {
	err := eventlog.InstallAsEventCreate(eventSource, eventlog.Info|eventlog.Warning|eventlog.Error)
	if err != nil && err.Error() == eventSource+" registry key already exists" {
		return nil
	}
	return err
}

func removeEventSource() { _ = eventlog.Remove(eventSource) }
