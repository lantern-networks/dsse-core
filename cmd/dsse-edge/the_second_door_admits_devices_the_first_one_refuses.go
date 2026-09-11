package main

import (
	"strings"
	"sync"
	"time"
)

// the_second_door_admits_devices_the_first_one_refuses.go — saying, on the record, that an agent-facing route
// answered a device the transport port would have turned away.
//
// ★★★ WHY (2026-08-22, measured end to end on the reference deployment with a real enrolled device).
//
// An administrator disables a device. The Console says disabled, the audit trail records it, and
// enrolledinventory.IsAdmitted starts answering false. On the TRANSPORT port that is enforced: the
// -transport-require-enrolled-identity gate runs inside VerifyConnection, and the TLS handshake fails.
// Measured, on a device first disabled and then deleted outright:
//
//	transport port 18543  /steer/agent-policy   connection refused at the handshake
//	device port     8443  /steer/agent-policy   HTTP 200 — the current steering policy
//	device port     8443  /bootstrap/trust-bundle HTTP 200 — the organization's trust material
//	device port     8443  /steer/region-endpoints HTTP 200
//
// So a laptop an administrator has disabled — the compromised-machine case this control exists for — keeps
// collecting the organization's enforcement configuration and PKI material from the second door, and every
// screen says it is disabled. Deleting it outright changes nothing either.
//
// ★ THIS IS WHAT the enrolment fold IS ACTUALLY WORTH. The single-port fold has been carried as tidiness — one address for
// an agent instead of two. It is not: the second port has no admission check at all, and folding these routes
// onto the transport port puts them behind the gate that already works. That is the argument for finishing it.
//
// ★ AND THIS REFUSES NOTHING, DELIBERATELY. Making the agent-facing routes fail closed tonight would turn any
// node whose ledger has not hydrated into a black hole for devices that are perfectly enrolled — and that is
// not hypothetical: on this same night reference-edge-region-b answered with an EMPTY enrolled ledger for
// every organization for as long as it was misconfigured. A gate that is armed while the thing it reads is
// still filling is the shape that has taken this lab down before. The enforcement belongs at the fold, where
// one gate serves one door. Until then the gap is at least no longer silent, which is the part that is free.

// deviceAdmissionObserver records, at most once per identity per hour, that an agent-facing route answered a
// device the enrolled ledger does not admit.
//
// restart-durability: ephemeral — deliberately, and it costs nothing an operator can see. This holds only
// "when did I last SAY this", the rate limiter for a log line; the finding itself lives in the log, which is
// shipped and retained. A restart makes the next unadmitted poll report immediately instead of waiting out
// the hour, which is the harmless direction: the worst case is one duplicate line after a restart, and the
// case that would matter — a disabled device going unreported because this process forgot it had already been
// reported — cannot happen.
//
// populated-by: side_effect — of an agent-facing handler answering a device: /steer/agent-policy today, and
// whichever agent routes the enrolment fold moves next. Being empty off that path is exactly right; a node no
// agent has dialled has nothing to report, and this is a rate limiter, not a record.
type deviceAdmissionObserver struct {
	mu   sync.Mutex
	said map[string]time.Time
}

var unadmittedDeviceReports = &deviceAdmissionObserver{said: map[string]time.Time{}}

// noteAnsweredWithoutAdmission is called from an agent-facing handler AFTER the device's identity is verified.
// admitted is what the enrolled ledger says; false means the transport port would have refused this
// handshake. Returns true when it said something, so a test can measure it.
//
// Rate limited per identity: a disabled agent polls, and a line per poll would bury the one that matters.
func (o *deviceAdmissionObserver) noteAnsweredWithoutAdmission(route, identity, tenantID string, admitted bool,
	now time.Time, say func(string, ...any)) bool {
	if admitted || o == nil || say == nil {
		return false
	}
	id := strings.ToLower(strings.TrimSpace(identity))
	if id == "" {
		return false
	}
	o.mu.Lock()
	last, seen := o.said[id]
	if seen && now.Sub(last) < time.Hour {
		o.mu.Unlock()
		return false
	}
	o.said[id] = now
	o.mu.Unlock()
	say("★★ device_answered_without_admission route=%q identity=%q tenant=%q — this device is NOT admitted by "+
		"the enrolled ledger (disabled, or removed), and the transport port would refuse its handshake. This "+
		"port has no admission check, so it was answered anyway. An administrator who disabled this device is "+
		"being told it is disabled while it still collects enforcement configuration. Closed by the enrolment fold, "+
		"which puts these routes behind the gate that already works.", route, id, strings.TrimSpace(tenantID))
	return true
}

// deviceIsAdmitted answers the ledger's question, and answers "yes" when there is no ledger to ask — a
// deployment with no enrolled inventory admits by other means, and reporting every device there would be a
// warning about the deployment's shape rather than about a device.
func deviceIsAdmitted(ledger interface{ IsAdmitted(string) bool }, identity string) bool {
	if ledger == nil {
		return true
	}
	return ledger.IsAdmitted(identity)
}
