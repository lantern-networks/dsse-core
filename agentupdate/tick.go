package agentupdate

// tick.go — the one decision a platform's update loop must not re-implement.

import (
	"fmt"
	"time"
)

// Reconcile closes out an attempt whose result only became visible after the process that started it went
// away. It reports whether it changed anything, and a sentence for the log.
//
// runningErr is passed in rather than swallowed because the interesting case is the one where the running
// version CANNOT be read. A box whose agent is not running after an install is exactly the box that may have
// been left without a network, and quietly treating that as "not reconciled" is right — Run will then report
// the interrupted attempt with its network warning, which at that point is TRUE rather than noise.
func Reconcile(j *Journal, running string, runningErr error, now time.Time) (bool, string) {
	if j == nil {
		return false, ""
	}
	interrupted, phase := j.Interrupted()
	if !interrupted {
		return false, ""
	}
	// ★ An attempt is an update or a ROLLBACK, and the sentences must not be interchangeable. Both record a
	// target and both are confirmed the same way — by the version that came back up — but "this device is on
	// 0.2.0" means the release landed in one case and that it had to be undone in the other, and an operator
	// reading a log during an incident is entitled to be told which.
	what := "an update to"
	if j.IsRollback() {
		what = "a rollback to"
	}
	if runningErr != nil {
		return false, fmt.Sprintf("%s %s is still recorded in phase %q and the running version cannot "+
			"be read (%v), so it stays open", what, j.TargetVersion, phase, runningErr)
	}
	// SameVersion, not string equality: the manifest names "0.2.1" and the device reports
	// "0.2.1+20260811035942". See the note on SameVersion — this one line is why every successful update on a
	// real Mac ended as `failed` with a false network alarm.
	if !SameVersion(running, j.TargetVersion) {
		return false, fmt.Sprintf("%s %s is still recorded in phase %q and this device is running %q, "+
			"so it did not land", what, j.TargetVersion, phase, running)
	}
	j.RecordSuccess(now)
	if j.IsRollback() {
		return true, fmt.Sprintf("ROLLED BACK to %s: this device is running it again, and %q stays refused on this "+
			"device until a different version is published", j.TargetVersion, j.FromVersion)
	}
	return true, fmt.Sprintf("attempt at %s completed: this device is now running it (the installer finished "+
		"after the updater that started it was replaced)", j.TargetVersion)
}
