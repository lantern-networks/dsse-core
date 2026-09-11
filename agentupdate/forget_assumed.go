package agentupdate

// forget_assumed.go — the supported way out of an "already reported" assumption that is wrong for a device.

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
)

// DeviceLockPath is where a device's update lock lives, given its journal.
//
// ★ ONE ANSWER, BECAUSE TWO PROCESSES ON ONE BOX MUST AGREE (2026-08-13, thirtieth review #22). Both agents
// computed this themselves, identically. A lock is worthless the moment two writers disagree about which file
// it is, and nothing would have failed loudly if one of the copies had drifted.
func DeviceLockPath(journalPath string) string {
	return filepath.Join(filepath.Dir(journalPath), "update.lock")
}

// ForgetAssumedOutcomeCommand clears a report marker that was ASSUMED rather than earned, so the outcome is
// owed again. It writes what an operator needs to read to out/errOut and returns a process exit code.
//
// ★★ ONE IMPLEMENTATION FOR BOTH AGENTS (2026-08-13, thirtieth review #22). This existed twice, verbatim —
// same logic, same sentences — with the review noting that "the next window rule will again ship on one OS".
// The assumption this undoes is about the BUILD that wrote the journal, not about the platform.
//
// ★ AND IT TAKES THE DEVICE LOCK, WHICH NEITHER COPY DID (carry-over #13, and #16 in this round: the same race
// had just been reproduced on Windows, the platform the command was written for). The service ticks on a timer
// and this is a command an operator runs by hand; without the lock both read the same journal and both write
// it, and the write that lands second wins. What is at stake is precisely whether an outcome is owed, so
// losing that race sends the fleet a duplicate or drops the report the operator was trying to recover.
func ForgetAssumedOutcomeCommand(journalPath string, out, errOut io.Writer) int {
	lock, lerr := LockDevice(DeviceLockPath(journalPath))
	if lerr != nil {
		if errors.Is(lerr, ErrLocked) {
			fmt.Fprintln(errOut, "dsse-updater: another update or rollback is in progress on this device, so the "+
				"report marker is not being touched. Try again once it finishes.")
			return 1
		}
		fmt.Fprintf(errOut, "dsse-updater: the device lock could not be taken: %v\n", lerr)
		return 1
	}
	defer lock.Release()

	j, err := LoadJournal(journalPath)
	if err != nil {
		fmt.Fprintf(errOut, "dsse-updater: the journal could not be read: %v\n", err)
		return 1
	}
	if !j.ForgetAssumedOutcome() {
		fmt.Fprintln(out, "dsse-updater: nothing to do — this device's report marker was EARNED by an outcome "+
			"that reached the outbox, or there is no terminal outcome to report. Clearing an earned marker would "+
			"send the same outcome to the fleet a second time, so this refuses to.")
		return 0
	}
	if serr := j.Save(journalPath); serr != nil {
		fmt.Fprintf(errOut, "dsse-updater: the change could not be recorded: %v\n", serr)
		return 1
	}
	fmt.Fprintf(out, "dsse-updater: the assumed report marker is cleared — this device owes the fleet %q again, "+
		"and the next pass will queue it.\n", j.OutcomeFingerprint())
	return 0
}
