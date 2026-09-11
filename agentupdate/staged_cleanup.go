package agentupdate

import "fmt"

// staged_cleanup.go — which staged installers a journal says this device is finished with.
//
// ★★ WHY THIS IS SHARED AND NOT WRITTEN TWICE (2026-08-14, thirty-first review #11). It WAS written twice, in
// clients/windows-wfp/updateplatform/tick.go and clients/macos/updater/main_darwin.go, as verbatim twins — and
// the macOS copy exists only because the rule shipped on Windows alone and had to be carried across by hand a
// round later. Its own comment says so: "a rule agreed for both platforms, shipped on one", and points at this
// hoist as the fix.
//
// That is the shape worth removing rather than the two lines it produced. A rule spelled out per platform is a
// rule that will next be changed on one of them, and the platform that misses it says nothing — a privileged
// installer accumulating at a predictable root-only path is silent by construction. The lab Mac had them.
//
// So the DECISION lives here, in the package both platforms already import, and each side supplies only the
// thing that genuinely differs: how to delete a file on that OS.

// StagedClearReason names why a staged installer is finished with, because the two cases are not the same
// event and an operator reading a note deserves to know which one they are looking at.
type StagedClearReason string

const (
	// StagedClearInstalled — the update landed. The bytes have done their job.
	StagedClearInstalled StagedClearReason = "installed"
	// StagedClearRefused — this device will never install this version: the release was withdrawn, or the
	// target is poisoned. Left alone, one of these accumulates per release the fleet changed its mind about.
	StagedClearRefused StagedClearReason = "refused"
)

// StagedClear is one staged installer to remove.
type StagedClear struct {
	Version string
	Reason  StagedClearReason
}

// StagedClears reports the staged installers this journal says are finished with.
//
// The rule, in one place, with the reasoning that was previously duplicated in both comments:
//
//   - COMPLETED: clear. Reconcile is the only writer of PhaseCompleted, so an update that lands passes this
//     exactly once — the next pass sees a phase that is not interrupted and never comes back. That is why a
//     failure is worth a note naming the path rather than a silent retry that will not happen.
//   - POISONED and not completed: clear. A version this device will never install has no reason to keep a
//     privileged installer on disk.
//   - FAILED (not poisoned, not completed): KEEP. The next window retries without re-downloading tens of
//     megabytes.
//   - ROLLED BACK: not reached, and note what its TargetVersion is — the OLD version it returned to, never the
//     build it escaped. The escaped build's bytes are keyed by FromVersion, are not named in any phase here,
//     and that is the right answer for evidence: what stops them being installed again is the poison, not a
//     deletion.
//
// The PHASE decides, not "was this a rollback", though they agree today: this asks what the journal now SAYS,
// and a third terminal outcome would otherwise be swept into "not a rollback, so delete it".
//
// A dry run clears nothing: it exists to say what would happen, and deleting a file is not saying.
func StagedClears(j *Journal, dryRun bool) []StagedClear {
	if j == nil || dryRun {
		return nil
	}
	version := j.TargetVersion
	if version == "" {
		return nil
	}
	if j.Phase == PhaseCompleted {
		return []StagedClear{{Version: version, Reason: StagedClearInstalled}}
	}
	if poisoned, _ := j.IsPoisoned(version); poisoned {
		return []StagedClear{{Version: version, Reason: StagedClearRefused}}
	}
	return nil
}

// StagedClearNote is what an operator is told when the removal failed.
//
// Shared for the same reason the decision is: the two platforms had drifted to "staged package" and "staged
// installer" for the same event, which is the visible edge of the same duplication. Best-effort is the rule
// everywhere — failing an update tick over housekeeping would stop the update path — so this text is the only
// consequence of a failure, and it has to say what to do about it.
func StagedClearNote(c StagedClear, err error) string {
	switch c.Reason {
	case StagedClearRefused:
		return fmt.Sprintf("the staged installer for the refused version %s could not be removed (%v)", c.Version, err)
	default:
		return fmt.Sprintf("the staged installer for %s could not be removed (%v) — it is a privileged install "+
			"waiting at a predictable path, so it is worth clearing by hand", c.Version, err)
	}
}
