//go:build windows

// log_windows.go — where this watchdog's output goes.
//
// It went nowhere. Measured on win-dev-1, 2026-08-09: no log file, no registered event source, nothing in
// Application or System. Under the SCM stdout is discarded, so every line this process writes — including the
// one that says "this is a reportable event, not a normal state" — was written for nobody. On the rate-limit
// cycle a box sat black-holed for 85 seconds and the limiter's carefully-worded refusal, the sentence that
// explains why nothing is coming to help, went to the same place.
//
// That is the silent-failure shape this tree keeps closing, in the component whose entire purpose is to act
// while nobody is watching. A recovery nobody can see afterwards leaves the machine in an UNSTEERED,
// unenforced state whose only evidence is that the box works again.
//
// Two sinks, because they answer different questions:
//
//   - a rolling file beside the binary, carrying EVERYTHING including the quiet ticks. It answers "was the
//     watchdog running, and what did it see?" — and "watching, all well" has to be distinguishable from "not
//     running at all", which a file that only records incidents cannot do.
//   - the Windows event log, carrying ONLY the reportable moments. It answers "did something happen to this
//     fleet?" for whatever collects Windows events. Writing every 15-second tick there would bury the handful
//     that matter and make the log unusable, so the quiet ones deliberately do not go.
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

// logFilePath puts the log beside the binary, matching dsse-steer.log so an operator finds both in one place.
func logFilePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "dsse-watchdog.log"
	}
	return filepath.Join(filepath.Dir(exe), "dsse-watchdog.log")
}

// redirectServiceLogs points stdout/stderr at the rolling file, timestamping each line. Same shape as the
// agent's log_windows.go on purpose: two components writing logs two different ways is one more thing to know
// during an incident.
//
// Best-effort by design. A watchdog that refused to run because it could not open its log would be trading
// the thing it protects for the record of protecting it.
func redirectServiceLogs() string {
	path := logFilePath()
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	// This process writes a line every tick, so it WILL grow. Rolled at 8 MB like the agent's.
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
	return path
}

// eventWriter is the event-log half. Nil when the source is not registered (a hand-deployed box that never
// ran --service-install, or a non-elevated run); every call is then a no-op, because losing the event log is
// not a reason to stop recovering machines.
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

// info/warn/err write one reportable event. The message is the same sentence written to the file, so an
// operator who finds one and goes looking for the other is not correlating two different vocabularies.
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
		// Say so in the FILE. An event that failed to be written is itself worth knowing about, and the file
		// is the sink that does not depend on registration.
		fmt.Printf("dsse-watchdog: could not write event %d to the Windows event log: %v\n", id, werr)
	}
}

// runEventSelfTest writes one probe event at every ID this component uses, plus one ABOVE the renderable
// range, and prints the command that reads them back.
//
// It was written to settle an open question and it kept its job after answering it. The question was which IDs
// EventCreate.exe renders; the answer (1..1001, measured on win-dev-1 2026-08-10) is now a constant and a test.
// What this still does is prove the constant is true of the box in front of you — a different Windows build,
// or a source someone registered by hand against a different message file, has a different table, and nothing
// else on the machine would ever say so.
//
// The out-of-range probe is the control. Without it a run where NOTHING renders looks the same as a run where
// everything does, and "all my probes rendered" would be equally consistent with the reader misreading them.
//
// Deliberately not run automatically and not part of any tick: it writes deliberately meaningless events, and
// an operator has to be able to tell those from the real ones. Each one says so in its first sentence.
func runEventSelfTest(evt *eventWriter) {
	type probe struct {
		id   uint32
		name string
	}
	probes := []probe{
		{evtRecovered, "recovered"},
		{evtRecoverFail, "recovery-failed"},
		{evtRateLimited, "rate-limited"},
		{evtReportOnly, "report-only"},
		{evtStarted, "started"},
		{evtCannotRecover, "cannot-recover"},
		{evtSteeringResumed, "steering-resumed"},
		{evtCleared, "cleared"},
	}
	// The control: one ID known to be outside the message table. If this one renders too, the table on this box
	// is not the one that was measured and the range in events.go does not describe it.
	const outOfRange = maxRenderableEventID + 2

	if evt == nil || evt.l == nil {
		fmt.Printf("dsse-watchdog: the %q event source is not registered on this box, so nothing can be written. "+
			"Run --service-install (elevated) first; this test has nothing to measure until then.\n", eventSource)
		return
	}
	fmt.Printf("dsse-watchdog: event-log self test. Writing %d probes at the IDs this component uses, and one at "+
		"%d as a control (expected NOT to render).\n", len(probes), outOfRange)
	for _, p := range probes {
		evt.warn(p.id, fmt.Sprintf("dsse-watchdog SELF TEST (not a real event): probe for event ID %d, %s. If you "+
			"can read this sentence in the rendered Message column, this ID renders.", p.id, p.name))
	}
	evt.warn(outOfRange, fmt.Sprintf("dsse-watchdog SELF TEST (not a real event): CONTROL probe at event ID %d, "+
		"which is outside the range EventCreate.exe renders. This one is EXPECTED to appear as \"the description "+
		"for Event ID ... cannot be found\". If it renders in full, the message table on this box is not the one "+
		"events.go was measured against.", outOfRange))

	fmt.Println(`dsse-watchdog: now read them back. The Message column is what is under test; EventData always
  carries the text and is not the question:

    Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='DsseWatchdog'} -MaxEvents 40 |
      Select-Object Id, @{n='Rendered';e={ if ($_.Message -and $_.Message -notmatch 'description for Event ID')
        { 'YES' } else { 'NO' } }}, @{n='Text';e={ $_.Properties[0].Value }} | Sort-Object Id | Format-Table -Wrap

  Expected on a box matching the measurement: every 1xx renders YES, the control renders NO.
  Anything else means this box's message table differs and events.go's range does not describe it.`)
}

// installEventSource registers the source so events are readable. Called from --service-install, which is
// already the elevated step; registration needs admin and there is no point failing the service install over
// it, so a failure is reported and the install continues.
func installEventSource() error {
	err := eventlog.InstallAsEventCreate(eventSource, eventlog.Info|eventlog.Warning|eventlog.Error)
	if err != nil && err.Error() == eventSource+" registry key already exists" {
		return nil
	}
	return err
}

func removeEventSource() { _ = eventlog.Remove(eventSource) }
