package main

// classify.go — turning one pass of updateplatform.Tick into something a person and a collector can both read.
//
// The mechanism lives in updateplatform: reconcile what is outstanding, learn what should be installed, stage
// it verified, and let agentupdate.Run decide. What is here is the reporting, and it is a separate file
// because the distinctions are the point rather than a formatting detail.
//
// ★ THREE FAILURES THAT MUST NOT COLLAPSE INTO ONE. A single "did not update" would make these
// indistinguishable, and the operator response to each is different:
//
//   - nothing published — the majority state on the majority of devices, on most days. Quiet.
//   - a manifest FAILED VERIFICATION — either the release process is broken or something is substituting
//     artefacts, and both need a person. Always reportable.
//   - something stopped the pass — an unreadable file, a journal that cannot be kept. Nothing was attempted.
//
// The second is the one this file exists for. A refusal that reads the same as "no release available" is a
// silent security control, which is the failure class this tree keeps closing.

import (
	"errors"
	"fmt"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/clients/windows-wfp/updateplatform"
)

// Result is one tick, classified.
type Result struct {
	Action string
	Reason string
	// Reportable marks what belongs in the event log rather than only in the rolling file. A tick that found
	// nothing to do is the overwhelming majority and must never be one of them.
	Reportable bool
}

// Actions added on top of agentupdate's, for the states that happen before Run is reached.
const (
	ActionIdle       = "idle"       // nothing published for this device
	ActionUnverified = "unverified" // a manifest arrived and was REFUSED. Always reportable.
	ActionBlocked    = "blocked"    // nothing could be attempted (unreadable manifest or journal, unkeepable record)
)

// Classify maps what one pass produced onto an action, a sentence, and whether anyone should be told.
func Classify(res updateplatform.TickResult, err error, source string) Result {
	switch {
	case errors.Is(err, updateplatform.ErrManifestRejected):
		return Result{Action: ActionUnverified, Reportable: true, Reason: fmt.Sprintf("REFUSED an update manifest "+
			"from %s: %v. Nothing was installed and this device stays on its current version, which is the safe "+
			"outcome — but a manifest that does not verify is either a broken release or a substitution, and both "+
			"need a person", source, err)}
	case errors.Is(err, updateplatform.ErrNoManifest):
		return Result{Action: ActionIdle, Reason: "no update is published for this device"}
	case err != nil:
		// Everything else that stopped a pass: a manifest file that exists but cannot be read, an unreadable
		// journal, a record that could not be kept. All mean nothing was attempted, and an unrecorded step is
		// a step nobody can recover from — so this is loud rather than quiet.
		//
		// Note what is NOT in this list: a network failure. The manifest is a file another component places,
		// so this process has no fetch to fail. If an HTTP source is ever added, "off the network" must get
		// its own quiet branch here rather than being filed as a device that cannot be updated.
		return Result{Action: ActionBlocked, Reportable: true, Reason: fmt.Sprintf("nothing was attempted on this "+
			"device: %v", err)}
	}

	r := Result{Action: res.Outcome.Action, Reason: res.Outcome.Reason}
	if r.Action == "" {
		r.Action = agentupdate.ActionNone
	}
	// Waiting is the designed steady state of a device inside a rollout and must not page anyone. `none` is a
	// device with nothing to do. Everything else is a state change or a refusal, and both are worth an event.
	r.Reportable = r.Action != agentupdate.ActionWaiting && r.Action != agentupdate.ActionNone
	// A closed-out attempt is reportable even when the pass then found nothing else to do: "this device
	// finished an update" is exactly the thing a fleet view is for, and it is the only moment it is knowable.
	if res.Reconciled {
		r.Reportable = true
		r.Reason = joinNotes(res.Notes) + r.Reason
	}
	return r
}

func joinNotes(notes []string) string {
	out := ""
	for _, n := range notes {
		out += n + "; "
	}
	return out
}

// DescribeManifest is what `--status` says about the document the whole decision rests on.
//
// ★ IT SAID NOTHING, and win-dev-1 found that by running both commands on one unchanged state: `--dry-run`
// reported "REFUSED an update manifest … unverified" and `--status` on the same box was silent. That is
// backwards for the command an operator runs FIRST. "Why is this device not updating" is asked about the
// manifest before anything else, and a refused manifest is, by this tree's own design, the event that means
// look tonight — so a device holding a substituted one was reporting a clean-looking status.
//
// It answers the same three questions the tick answers, from the same source, so the two cannot disagree:
// is anything there, does it verify, and what does it offer.
func DescribeManifest(m agentupdate.Manifest, err error, source string) string {
	switch {
	case errors.Is(err, updateplatform.ErrNoManifest):
		return "none published for this device (nothing to install; this is the ordinary state)"
	case errors.Is(err, updateplatform.ErrManifestRejected):
		// The loud one. Deliberately not softened into "invalid": a manifest that fails verification is either
		// a broken release or a substitution, and both need a person tonight.
		return fmt.Sprintf("★ REFUSED — %v. Nothing will be installed, which is the safe outcome, but a manifest "+
			"that does not verify is either a broken release or a substitution and needs looking at now", err)
	case err != nil:
		return fmt.Sprintf("could not be read from %s: %v", source, err)
	}
	offer := fmt.Sprintf("%s for %s/%s, delivery=%s, valid until %s", m.Version, m.Platform, m.Arch, m.Delivery, m.NotAfter)
	if m.Delivery == agentupdate.DeliveryMDM {
		// Worth saying plainly: an operator seeing a version offered and nothing happening would otherwise
		// reasonably suspect the updater.
		offer += " — DSSE will NOT install this one; the MDM delivers it and DSSE only reports what landed"
	}
	return "verified, offering " + offer
}
