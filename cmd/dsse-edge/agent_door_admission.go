package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"strings"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/revocation"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// agent_door_admission.go — the roster, applied at the door devices actually arrive at.
//
// ★★★ REMOVAL WAS NOT REVOCATION, AND A CHECK THAT WALKED IT SAID SO IN ONE LINE (2026-08-24):
//
//	FAIL  a removed device can no longer steer — it was REMOVED from the enrolled inventory and was
//	      still admitted (200 Connection Established)
//
// The agent-facing door asked one question — does this certificate chain to a device CA I know — and never
// asked the second one, which is whether the deployment still admits the machine holding it. A certificate
// outlives the enrolment that produced it, so an administrator who removed or blocked a device was told it
// was gone while it went on carrying traffic with what it already had.
//
// ★★ THE PREDICATE IS THE (T) LISTENER'S, NOT A SECOND OPINION. Revocation overlay first, then the enrolled
// ledger — the same order and the same objects that secure_transport.go consults, because two admission rules
// that are supposed to agree eventually stop agreeing, and the one nobody walks is the one that drifts.
//
// ★★★ AND IT ONLY JUDGES CERTIFICATES THAT CLAIM TO BE DEVICES. The client-CA pool on this listener holds two
// unrelated kinds of anchor: the organizations' device CAs, and the operator anchors an Edge's own shipping
// identity is issued by. An Edge shipping audit to the control plane presents the second kind and is in no
// device roster anywhere — judging it here would kill every audit shipment at the handshake, which is the
// exact failure the pool's own history records. A certificate that resolves to no registered device CA is not
// making a device claim, and this says nothing about it.
//
// ★ A DEVICE PRESENTING NOTHING IS ALSO LEFT ALONE. /enroll is served on this door and an enrolling device
// has no certificate yet. Refusing here would mean a deployment where nobody can ever become a member.

// agentDoorAdmission is the check the agent-facing door runs, or nil when this node has no roster to apply.
var agentDoorAdmission func(tls.ConnectionState) error

// setAgentDoorAdmission installs the roster check. Called once, before anything serves.
func setAgentDoorAdmission(reg *tenantca.TenantCARegistry, ledger *enrolledinventory.Ledger,
	revocations *revocation.AdmissionRevocations) {
	if reg == nil || (ledger == nil && revocations == nil) {
		// Nothing to consult. Saying so by staying nil is better than installing a check that admits
		// everything: a hook that always passes reads, later, like a hook that is working.
		return
	}
	agentDoorAdmission = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
			return nil // no device claim was made
		}
		if _, isDevice := reg.TenantForVerifiedChains(cs.VerifiedChains); !isDevice {
			return nil // an operator-issued certificate, not a device of any organization
		}
		id := transportIdentityFromLeaf(cs.PeerCertificates[0])
		if strings.TrimSpace(id) == "" {
			log.Printf("agent_door_denied reason=no_identity")
			return fmt.Errorf("agent door: the client certificate has no usable identity")
		}
		if revocations != nil {
			if reason, gone := revocations.IsRevoked(id); gone {
				log.Printf("agent_door_denied reason=revoked identity=%q revoke_reason=%q", id, reason)
				return fmt.Errorf("agent door: identity %q is revoked (%s)", id, reason)
			}
		}
		// ★★★ "KNOWN AND REFUSED", NOT "NOT KNOWN TO BE ALLOWED" (2026-08-24, the first version locked the
		// fleet out). A device enrols on one Edge; the other Edges learn about it through the control plane a
		// poll later. Refusing an identity this node has simply not heard of yet refuses every agent that
		// enrols and connects a second afterwards — which is every agent. Measured: the enrolled device that
		// had just passed this same check was refused at the handshake on the other node.
		//
		// ★★ WHAT THIS DOES AND DOES NOT STOP. Blocking a device stops it, everywhere, within a poll: the
		// entry stays and says so. REMOVING it does not — the entry vanishes, which is indistinguishable from
		// a device this node has not been told about, and the machine goes on steering with the certificate it
		// holds. Closing that needs the removal to leave something behind (a tombstone the fleet carries), and
		// until it does, "blocked" is the operation that means what an operator thinks removal means.
		if ledger != nil && ledger.IsRefused(id) {
			log.Printf("agent_door_denied reason=blocked identity=%q", id)
			return fmt.Errorf("agent door: identity %q is blocked", id)
		}
		return nil
	}
	// ★★★ AND THE SAME JUDGEMENT, ASKABLE WITHOUT A NEW HANDSHAKE (2026-08-25, measured on a real endpoint).
	//
	// Everything above is a TLS hook: it runs when a connection is MADE. A real agent carries every flow on a
	// pool of long-lived multiplexed connections — twelve of them, twelve flows each — so blocking a device
	// stopped nothing it was already holding. Measured on win-dev-1: an administrator pressed block, the
	// heartbeat was refused at the handshake (so the block WAS in effect), and the machine went on browsing
	// for the whole observation window, opening NEW flows on the connections it already had.
	//
	//	13:37:03  disable -> 200
	//	13:37:26  line.me 200, steer_mux_forwarded flow=170,171,172
	//	13:37:31  heartbeat: remote error: tls: bad certificate
	//
	// "Stops making new connections" and "stops" are different things, and nothing on the screen told them
	// apart. The synthetic device this deployment checks with holds ONE connection, which is why the check
	// read nine seconds: it had to reconnect to do anything at all.
	agentIdentityRefused = func(id string) (string, bool) {
		id = strings.TrimSpace(id)
		if id == "" {
			return "", false
		}
		if revocations != nil {
			if reason, gone := revocations.IsRevoked(id); gone {
				return "revoked (" + reason + ")", true
			}
		}
		if ledger != nil && ledger.IsRefused(id) {
			return "blocked", true
		}
		return "", false
	}
}

// agentIdentityRefused answers "is this device refused RIGHT NOW", for a connection that is already open.
// Nil until setAgentDoorAdmission has something to consult — a nil check that always says "not refused"
// reads, later, exactly like a check that is working.
var agentIdentityRefused func(string) (string, bool)

// agentIdentityRefusedNow is the nil-safe form for the flow paths.
func agentIdentityRefusedNow(id string) (string, bool) {
	if agentIdentityRefused == nil {
		return "", false
	}
	return agentIdentityRefused(id)
}
