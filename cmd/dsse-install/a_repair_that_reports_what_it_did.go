package main

import (
	"fmt"
	"os"
	"time"
)

// a_repair_that_reports_what_it_did.go — regenerating a derived file, and saying which files actually changed.
//
// ★★★ THE REPAIR PRINTED THE NAMES OF FILES IT HAD LEFT ALONE (2026-08-31, measured on a live deployment
// while trying to deliver a fix to it).
//
// Each generated-file writer opens with "if the file exists, return nil — an operator has edited it". That is
// right on an INSTALL: a second run must not throw away somebody's edits. repairDerivedFiles then reused those
// same writers to do the opposite job — "write what can be DERIVED from authorities already on disk", the path
// whose entire purpose is to bring a running deployment up to the current installer — so every file that
// existed, which is all of them, was skipped. And it printed:
//
//	rewrote this deployment's generated files from the current installer:
//	  the launch scripts
//	  haproxy.cfg (the region's front door)
//	  haproxy-edge.cfg
//	  ...
//
// Nothing had been rewritten. The fix for the agent plane's door was in the binary on the machine, the
// operator was told it had been applied, and the file on disk was the one from the original install. An
// installer fix could not reach a running deployment by any route, and the report said it had.
//
// So: a repair regenerates, keeps the previous file beside it, and reports per file what actually happened.
// An install still leaves an existing file alone — that guard was never the problem.
var regeneratingDerivedFiles bool

// derivedFileOutcome is what happened to one generated file, for the report.
type derivedFileOutcome struct {
	name    string
	changed bool
	kept    string // the backup, when one was made
	note    string
}

var derivedFileOutcomes []derivedFileOutcome

// keepWhatIsThere reports whether a writer should leave an existing file alone. On an install it always does.
// On a repair it does not — but it saves what was there first, so an operator's edits are recoverable by
// name rather than by memory.
func keepWhatIsThere(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false // nothing there: write it
	}
	if !regeneratingDerivedFiles {
		return true // an install: never overwrite what somebody authored
	}
	backup := path + ".before-repair-" + time.Now().UTC().Format("20060102T150405Z")
	if existing, rerr := os.ReadFile(path); rerr == nil {
		if werr := os.WriteFile(backup, existing, 0o600); werr == nil {
			noteDerivedFile(path, backup, "")
			return false
		}
	}
	// ★ IF THE PREVIOUS CONTENT CANNOT BE SAVED, IT IS NOT OVERWRITTEN. A repair that destroys the only copy
	// of a hand-edited file to deliver an improvement is not a repair.
	noteDerivedFile(path, "", "left alone: its previous content could not be saved first")
	return true
}

func noteDerivedFile(path, backup, note string) {
	derivedFileOutcomes = append(derivedFileOutcomes, derivedFileOutcome{
		name: path, changed: note == "", kept: backup, note: note,
	})
}

// reportDerivedFiles prints what the repair actually did, file by file. Named separately from the act list
// because the act list is what was ATTEMPTED, and printing that as what happened is the defect this exists to
// prevent from coming back.
func reportDerivedFiles() {
	if len(derivedFileOutcomes) == 0 {
		fmt.Printf("  no generated file needed rewriting — every one of them already matches this installer.\n")
		return
	}
	for _, o := range derivedFileOutcomes {
		switch {
		case !o.changed:
			fmt.Printf("  ! %s — %s\n", o.name, o.note)
		case o.kept != "":
			fmt.Printf("  rewritten %s (the previous file is beside it as %s)\n", o.name, o.kept)
			// ★★★ PUT IT BACK THROUGH THE SAME FILE, NEVER BY RENAME (2026-08-31, cost a region's door 15
			// minutes while every host-side check said it was restored). These files are bind-mounted into
			// their containers one FILE at a time, so a container is attached to the file's INODE, not to its
			// path. `mv backup config` gives the path a new inode: the host then shows the restored config,
			// the container goes on reading the file that no longer has a name, and a restart does not help
			// because there is nothing new at the inode it holds. Writing THROUGH the existing file keeps the
			// inode, and then a restart is enough.
			fmt.Printf("      to put it back:  cat %s > %s   ← through the file, not `mv` (the container is attached to the file, not its name)\n", o.kept, o.name)
		default:
			fmt.Printf("  rewritten %s\n", o.name)
		}
	}
	fmt.Printf("  ★ Nothing changes until the deployment is restarted.\n")
}
