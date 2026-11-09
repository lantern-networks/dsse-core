package main

// updater_restart.go — putting DsseUpdater's verification conditions in force, as a sequence that can be tested.
//
// ★★★ WRITTEN, STOPPED AND STARTED ARE THREE STATES (2026-11-04). The service configuration
// and the running process are different things, and a restart has two halves that can each fail:
//
//   - The configuration written and the stop failed: a rerun found nothing left to write and reported success while
//     the process kept running without the conditions.
//   - The stop succeeded and the start failed: a rerun found the service Stopped, could not tell that this program
//     had stopped it, left it stopped and cleared the record — so updates stayed off until somebody noticed.
//   - The record itself could not be written or read: treated as "nothing owed".
//
// So a marker records, BEFORE each step, what this program may still owe:
//
//	intent   conditions may be written; if they were, a running process must be restarted
//	stopped  this program is stopping, or has stopped, the service and owes the start
//
// "stopped" is written before the stop is requested, so a run that dies anywhere between the stop and the start
// leaves the start owed. The marker is cleared only once nothing is owed. A marker that cannot be written stops
// the sequence before the step it would have recorded; one that cannot be read is an error, never "absent". A
// service that was already stopped when this program found it, with no "stopped" record — stopped by an
// administrator, or not yet started — is left stopped: its start type decides.
//
// One case is decided in favour of the restart: if the stop failed after "stopped" was written and an
// administrator then stopped the service by hand, a rerun starts it. The record cannot tell those two apart.

import "fmt"

const (
	updaterMarkerIntent  = "intent"
	updaterMarkerStopped = "stopped"
)

// updaterOps are the operations the sequence needs. The Windows implementation drives the service manager and a
// file under %ProgramData%\DSSE; tests substitute them.
type updaterOps interface {
	// ReadMarker returns "" when no marker exists, and an error when one may exist but cannot be read.
	ReadMarker() (string, error)
	WriteMarker(state string) error
	ClearMarker() error
	// ApplyConditions restores the saved conditions and adopts the profile's update keys where the device has none.
	ApplyConditions() (changed bool, notes []string, err error)
	// Running reports whether the service is running or starting.
	Running() (bool, error)
	// Stop stops the service and waits until it is stopped.
	Stop() error
	// Start starts the service and waits until it is running.
	Start() error
}

func putUpdaterConditionsInForce(ops updaterOps) ([]string, error) {
	earlier, err := ops.ReadMarker()
	if err != nil {
		return nil, fmt.Errorf("the record of an earlier DsseUpdater restart cannot be read, so it is not known "+
			"whether a restart is owed: %w", err)
	}
	if earlier != "" && earlier != updaterMarkerIntent && earlier != updaterMarkerStopped {
		return nil, fmt.Errorf("the record of an earlier DsseUpdater restart says %q, which this program does not "+
			"write; nothing is changed until it is examined", earlier)
	}
	if earlier == "" {
		if err := ops.WriteMarker(updaterMarkerIntent); err != nil {
			return nil, fmt.Errorf("could not record the DsseUpdater change before making it, so nothing was "+
				"changed: %w", err)
		}
	}
	changed, notes, err := ops.ApplyConditions()
	if err != nil {
		// The marker stays: whatever was written before the failure may still need a restart.
		return notes, err
	}
	running, err := ops.Running()
	if err != nil {
		return notes, fmt.Errorf("query DsseUpdater: %w", err)
	}
	switch {
	case running && (changed || earlier != ""):
		if err := ops.WriteMarker(updaterMarkerStopped); err != nil {
			return notes, fmt.Errorf("DsseUpdater must be restarted to read its conditions, but the record that "+
				"would let a rerun finish the restart could not be written, so it was not stopped: %w", err)
		}
		if err := ops.Stop(); err != nil {
			return notes, fmt.Errorf("DsseUpdater's conditions changed but it could not be stopped to read "+
				"them; run provisioning again to complete the restart: %w", err)
		}
		if err := ops.Start(); err != nil {
			return notes, fmt.Errorf("DsseUpdater was stopped to read its new conditions and could not be "+
				"started; run provisioning again to start it: %w", err)
		}
		if earlier != "" && !changed {
			notes = append(notes, "DsseUpdater was restarted to complete a restart an earlier run could not finish")
		}
	case !running && earlier == updaterMarkerStopped:
		// This program stopped it earlier and the start did not complete.
		if err := ops.Start(); err != nil {
			return notes, fmt.Errorf("DsseUpdater is still stopped after an earlier restart and starting it "+
				"failed again, so the start is still owed: %w", err)
		}
		notes = append(notes, "DsseUpdater was started to complete a restart an earlier run could not finish")
	}
	if err := ops.ClearMarker(); err != nil {
		return notes, fmt.Errorf("the conditions are in force but the restart record could not be cleared, so a "+
			"later run may restart DsseUpdater once more: %w", err)
	}
	return notes, nil
}
