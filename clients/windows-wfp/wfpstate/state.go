// Package wfpstate reads, and reasons about, what the WFP callout driver is doing RIGHT NOW.
//
// It is a package rather than a file inside one command because TWO commands need the answer and must not
// disagree about it: dsse-steer (which disarms and must confirm the disarm landed) and dsse-watchdog (which
// exists to notice when nobody disarmed at all). Both are package main, so the only way to share one decoder
// is a library — and two hand-written copies of one C memory layout drift silently, with the symptom being a
// wrong "armed" bit: either a black hole ignored, or a healthy box's steering torn down.
//
// Nothing here is //go:build windows. It is pure decoding and pure decision, so it compiles and is tested on
// any host; only the DeviceIoControl call that produces the bytes is Windows-only. The split is deliberate —
// these decisions determine whether a machine has a network, and "it could not be tested because it needs
// Windows" is a poor reason for them to go unexercised.
//
// WHY THIS EXISTS AT ALL. The driver's redirect policy is cleared by IOCTL_DSSE_CLEAR_POLICY and nothing else.
// Every caller of it lives in this agent — Close(), onDisarm, --mode recover — so if the agent dies without
// running one of them (crash, TerminateProcess, an installer's files-in-use kill, power loss) the redirect
// stays armed and points at a local port with no listener. That is not fail-open; every connection is
// refused, and it ends when a human arrives. Until DSSE_STATS version 3 nothing could even ask whether the
// box was in that state: the struct carried counters only, and this agent used the IOCTL purely as a
// liveness probe without parsing a single field of the reply.
package wfpstate

import (
	"encoding/binary"
	"fmt"
)

// StatsVersion is the DSSE_STATS revision this package understands. Must equal DSSE_STATS_VERSION in
// driver/dsse_wfp.h. Version 3 appended the state block; the counters before it are unchanged.
const StatsVersion = 4

// Offsets into DSSE_STATS. The struct sits inside #include <pshpack1.h>, so it is byte-packed and every
// offset is the plain running sum of the preceding fields: fourteen 32-bit counters (Version through
// LastAcquireWritableStatus) occupy 0..55, and the version-3 state block follows.
//
// These are NOT trusted from this comment. wfp_driver_state_test.go re-derives them by PARSING
// driver/dsse_wfp.h and fails if they disagree — the header and this decoder are two descriptions of one
// memory layout, and the only two things that can keep them equal are a shared generator or a test. Reading
// the wrong offsets here would not fail loudly; it would report a plausible wrong answer about whether a
// machine is on the network, which is the one kind of wrong this file exists to prevent.
const (
	OffVersion           = 0
	OffPolicyArmed       = 56
	OffPolicyProxyPID    = 60
	OffPolicyLocalPort   = 64
	OffPolicyObserveOnly = 66
	OffOwnerPresent      = 68
	OffOwnerDisarmOnExit = 72
	StatsV3Size          = 76
	OffCaptiveActive     = 76
	OffCaptiveExpired    = 80
	OffCaptiveGeneration = 84
	OffCaptiveDeadline   = 92
	StatsV4Size          = 100
)

// State is the answer to "is this box steering, and is anyone behind it".
type State struct {
	// Armed: a redirect policy is in force. Every non-bypassed connect is being sent to LocalPort.
	Armed bool
	// ObserveOnly: armed, but recording rather than redirecting. Cannot cause an outage — kept separate so a
	// watchdog does not "recover" a box that was never steering in the first place.
	ObserveOnly bool
	// OwnerPresent: an ARM_OWNER handle is open, i.e. the agent that accepts the redirected connections is
	// alive. Armed && !OwnerPresent is the black hole.
	OwnerPresent bool
	// DisarmOnExit: the driver will clear the policy when the owner handle closes. This is the endpoint's
	// install-time posture, not a runtime choice — false means this endpoint was installed fail-closed and is
	// SUPPOSED to stop passing traffic when its agent dies.
	DisarmOnExit         bool
	ProxyPID             uint32
	LocalPort            uint16
	CaptiveSupported     bool
	CaptiveActive        bool
	CaptiveExpired       bool
	CaptiveGeneration    uint64
	CaptiveDeadline100ns uint64
}

// Parse decodes an IOCTL_DSSE_GET_STATS reply.
//
// Fail-closed on ambiguity: a short buffer or an unrecognised version is an ERROR, never a zero value. A
// zero-valued State reads as "not armed, nothing wrong", which is precisely the wrong answer to give
// about a driver you failed to interrogate — the caller would then decide no recovery was needed. "I could
// not tell" and "everything is fine" must not be the same value.
func Parse(buf []byte) (State, error) {
	if len(buf) < 4 {
		return State{}, fmt.Errorf("wfp stats: reply is %d bytes, too short to carry a version", len(buf))
	}
	version := binary.LittleEndian.Uint32(buf[OffVersion:])
	if version < 3 {
		return State{}, fmt.Errorf("wfp stats: driver reports version %d, this agent needs %d "+
			"(the loaded driver predates the arming-state block — it cannot say whether it is redirecting)",
			version, 3)
	}
	// A NEWER driver is accepted: the struct grows append-only, so the fields below are still where they are.
	if len(buf) < StatsV3Size {
		return State{}, fmt.Errorf("wfp stats: reply is %d bytes, need %d for the state block",
			len(buf), StatsV3Size)
	}
	state := State{
		Armed:        binary.LittleEndian.Uint32(buf[OffPolicyArmed:]) != 0,
		ProxyPID:     binary.LittleEndian.Uint32(buf[OffPolicyProxyPID:]),
		LocalPort:    binary.LittleEndian.Uint16(buf[OffPolicyLocalPort:]),
		ObserveOnly:  binary.LittleEndian.Uint16(buf[OffPolicyObserveOnly:]) != 0,
		OwnerPresent: binary.LittleEndian.Uint32(buf[OffOwnerPresent:]) != 0,
		DisarmOnExit: binary.LittleEndian.Uint32(buf[OffOwnerDisarmOnExit:]) != 0,
	}
	if version >= 4 {
		if len(buf) < StatsV4Size {
			return State{}, fmt.Errorf("wfp stats: truncated captive state: %d bytes, need %d", len(buf), StatsV4Size)
		}
		state.CaptiveSupported = true
		state.CaptiveActive = binary.LittleEndian.Uint32(buf[OffCaptiveActive:]) != 0
		state.CaptiveExpired = binary.LittleEndian.Uint32(buf[OffCaptiveExpired:]) != 0
		state.CaptiveGeneration = binary.LittleEndian.Uint64(buf[OffCaptiveGeneration:])
		state.CaptiveDeadline100ns = binary.LittleEndian.Uint64(buf[OffCaptiveDeadline:])
		if state.CaptiveActive && (state.CaptiveGeneration == 0 || state.CaptiveDeadline100ns == 0) {
			return State{}, fmt.Errorf("wfp stats: invalid active captive deadline")
		}
		if state.CaptiveExpired && !state.CaptiveActive {
			return State{}, fmt.Errorf("wfp stats: expired captive deadline without active guard")
		}
	}
	return state, nil
}

// BlackHole reports the one state that takes a machine off the network without anyone deciding to: the driver
// is redirecting every connect to a local port whose listener is gone.
//
// ObserveOnly is excluded because such a policy permits the flow and records it; there is nothing to recover.
func (s State) BlackHole() bool {
	return s.Armed && !s.ObserveOnly && !s.OwnerPresent
}

// String is what an operator reads in a log line, so it names the situation rather than dumping fields.
func (s State) String() string {
	switch {
	case s.CaptiveActive:
		return fmt.Sprintf("wfp_state=captive_deadline active=true expired=%t generation=%d owner_present=%t (new direct flows denied after monotonic deadline; established flows retained)", s.CaptiveExpired, s.CaptiveGeneration, s.OwnerPresent)
	case !s.Armed:
		return "wfp_state=disarmed (not steering; traffic goes direct)"
	case s.ObserveOnly:
		return fmt.Sprintf("wfp_state=observe_only owner_present=%t (recording, not redirecting)", s.OwnerPresent)
	case s.BlackHole():
		return fmt.Sprintf("wfp_state=BLACK_HOLE armed=true owner_present=false proxy_pid=%d local_port=%d "+
			"disarm_on_exit=%t — every connection on this box is being refused", s.ProxyPID, s.LocalPort, s.DisarmOnExit)
	default:
		return fmt.Sprintf("wfp_state=steering proxy_pid=%d local_port=%d disarm_on_exit=%t", s.ProxyPID, s.LocalPort, s.DisarmOnExit)
	}
}

// PostureLabel spells out, in the startup log, what this endpoint will do if the agent dies —
// because "disarm_on_agent_exit=false" is a true statement that tells an operator nothing about the
// consequence, and the consequence is that the machine stops passing traffic.
func PostureLabel(disarmOnExit bool) string {
	if disarmOnExit {
		return "fail-open — if this agent dies the driver stops redirecting and the box keeps its network, unsteered"
	}
	return "fail-closed — if this agent dies the driver keeps redirecting and the box refuses connections until recovery"
}

// DisarmVerification is the result of checking that a disarm actually took effect.
type DisarmVerification struct {
	Verified bool   // the driver confirms it is no longer redirecting
	Reason   string // why not, when Verified is false
	State    State  // what the driver reported, when it could be read
}

// VerifyDisarmed turns a post-disarm state read into a verdict.
//
// Every disarm path in this agent is written "best effort" — removePolicy's own comment says so. Best effort
// is fine as an implementation stance and useless as a claim: a disarm that silently failed leaves exactly
// the black hole the disarm existed to prevent, and the log line said it succeeded. So the disarm is not
// finished until the driver has been asked again.
//
// A read error is NOT treated as disarmed. If the driver cannot be interrogated, the honest verdict is "I do
// not know", and the caller must act as though the box may still be armed.
func VerifyDisarmed(state State, readErr error) DisarmVerification {
	if readErr != nil {
		return DisarmVerification{
			Reason: "could not read the driver's state after disarming, so it is unknown whether the " +
				"redirect is still in force: " + readErr.Error(),
		}
	}
	if state.CaptiveActive {
		return DisarmVerification{Reason: "independent captive deadline remains active: " + state.String(), State: state}
	}
	if state.Armed {
		return DisarmVerification{
			Reason: "the driver still reports a redirect policy in force after the clear was issued: " + state.String(),
			State:  state,
		}
	}
	return DisarmVerification{Verified: true, State: state}
}
