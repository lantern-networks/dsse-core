package main

import "strings"

// vm_egress.go — whether virtual machines on this device may reach the internet, and how that decision is
// carried. Split from the Windows half so the DECISION can be tested anywhere; see vm_egress_windows.go for
// the enforcement.
//
// ★★★ A VIRTUAL MACHINE ON THIS DEVICE HAS ITS OWN NETWORK STACK AND THIS AGENT DOES NOT SEE IT (2026-09-01,
// measured on win-dev-1).
//
// The capture is connect-time classification of sockets on THIS Windows TCP/IP stack. A WSL2 distro, and any
// Hyper-V guest, has its own stack and leaves through a virtual switch — so it never reaches the classifier.
// Side by side on one box:
//
//	Windows itself   chain=ORG      egress 35.75.123.238   the deployment's Edge
//	inside WSL       public CA      egress 116.82.46.71    the site's own uplink
//
// while this agent went on printing target=ALL-outbound-tcp. Nothing broke, so nothing reported it.
//
// ★ AND IT NEEDS NO ADMINISTRATOR. Measured with a real standard account (Users only, not Administrators):
// `wsl --import` of a rootfs into the user's own %LOCALAPPDATA% succeeded with no elevation prompt and egressed
// unmediated. Enabling the WSL feature itself DOES require an administrator — so this is a hole on a box where
// it is already enabled, which on Windows 11 is increasingly the default. The imported distro named none of
// this agent's bypass_apps and did not need to: a separate stack is never classified at all.
//
// This product's job is to make reaching administrator hard. A standard user stepping around the whole
// steering layer is therefore an enforcement hole, not a post-compromise detail.
//
// ★★ THE DECISION IS THE ORGANIZATION'S, NOT THIS AGENT'S. The signed profile carries it
// (installprofile.VMEgress), blocked by default, and letting them out takes the same two keys as fail-open —
// "we cannot inspect this" and "we let it out anyway" are two decisions and the operator makes both. An
// organization that runs virtual machines says so on a screen instead of turning steering off.

// vmEgressDecision is what this agent was told to do about virtual machines on this device.
type vmEgressDecision struct {
	// Block is what to enforce. TRUE for every profile that does not say otherwise, including every profile
	// issued before the field existed: the promise this agent makes about outbound traffic is what decides
	// the absent case.
	Block bool
	// Authored records whether the profile stated it, so the log can tell "the organization chose to let them
	// out" from "nobody has decided yet and this is the safe default".
	Authored bool
}

// vmEgressFromProfile reads the decision. The strings are installprofile's, matched loosely on case and space
// because a value that arrives with either is the same decision, and a value neither side knows blocks —
// a typo must not become permission.
func vmEgressFromProfile(value string, acknowledged bool) vmEgressDecision {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "allowed":
		// Both keys, or it is not a decision. The control plane enforces this too; doing it here as well means
		// a profile that somehow carries one without the other cannot open the box.
		return vmEgressDecision{Block: !acknowledged, Authored: true}
	case "blocked":
		return vmEgressDecision{Block: true, Authored: true}
	default:
		return vmEgressDecision{Block: true, Authored: false}
	}
}

// Line is what the agent says at startup, so an operator reading a log knows which of the three states this
// box is in without going to look at the profile.
func (d vmEgressDecision) Line() string {
	switch {
	case d.Block && d.Authored:
		return "virtual machines on this device are blocked from reaching the internet — the organization chose this"
	case d.Block:
		return "virtual machines on this device are blocked from reaching the internet — nobody has chosen yet, " +
			"and this agent does not see their traffic, so it does not let it out"
	default:
		return "★ virtual machines on this device REACH THE INTERNET UNINSPECTED — the organization chose this. " +
			"Their traffic is not steered, not recorded and no rule is applied to it, and any user of this box " +
			"can start one without administrator rights"
	}
}
