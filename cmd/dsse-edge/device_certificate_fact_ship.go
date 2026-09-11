package main

import (
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

// device_certificate_fact_ship.go — telling the control plane which certificate each device is presenting.
//
// ★★★ THE GATE THAT COULD NEVER OPEN (2026-08-23, measured). Withdrawing a device CA is refused while any
// enrolled device might still be admitted under it — a good rule, and the one thing standing between an
// operator and a fleet-wide lockout. Its evidence is what THIS node has seen devices present at the (T)
// handshake.
//
// A control plane never terminates a device handshake, so it sees none of that. Measured: a CA registered on
// the control plane could not be withdrawn there, because all three enrolled devices came back as "never seen
// presenting a certificate on this node". The authority could not retract what it had itself issued.
//
// The evidence has to come from the FLEET. It travels the way the other device reports travel — on a shipped
// stream, through the spool that survives a control-plane outage, folded in by the ingest receiver.
//
// ★ THE GATE STAYS AS IT IS. Nothing here loosens it: an unseen device still blocks a withdrawal. What changes
// is that "unseen" starts meaning "no Edge in this deployment has seen it" instead of "the node you happen to
// be asking has not". A gate answering from the wrong evidence is not a stricter gate, it is a broken one.

const deviceCertificateFactStream = "device_certificates.log.jsonl"

// deviceCertificateShipWriter is the log writer facts are shipped through. An atomic pointer because
// observeChain runs on the handshake path — from several goroutines, before and after the writer exists — and
// this must never be the thing that blocks or panics a TLS handshake.
var deviceCertificateShipWriter atomic.Pointer[logs.Writer]

// setDeviceCertificateShipWriter arms shipping. Until it is called, facts are recorded locally and not shipped,
// which is the correct behaviour for a node that has no control plane to ship to.
func setDeviceCertificateShipWriter(w *logs.Writer) {
	if w != nil {
		deviceCertificateShipWriter.Store(w)
	}
}

// shipDeviceCertificateFact writes one fact to the shipped stream. Best-effort by construction: it runs on a
// handshake, and a device connecting must never wait on the control plane being reachable. The shipper's spool
// is what makes "best-effort" mean "delivered later" rather than "lost".
func shipDeviceCertificateFact(fact deviceCertificateFact) {
	writer := deviceCertificateShipWriter.Load()
	if writer == nil {
		return
	}
	row, err := json.Marshal(fact)
	if err != nil {
		return
	}
	var fields map[string]any
	if json.Unmarshal(row, &fields) != nil {
		return
	}
	fields["kind"] = "device_certificate_fact"
	_ = writer.Append(deviceCertificateFactStream, fields)
}

// deviceCertificateReshipEvery is how often an Edge re-sends everything it knows, regardless of change.
//
// ★★★ SHIPPING ON CHANGE ALONE IS NOT ENOUGH, and two measurements say so (2026-08-23).
//
// The control plane's view of this is IN MEMORY — deliberately, because every entry reappears within seconds of
// a device reconnecting. That is true for an EDGE, which terminates the handshakes. It is not true for a
// control plane, which terminates none: after a restart its view would be empty and, with change-only
// shipping, would stay empty until some device happened to renew. The withdrawal gate would then refuse every
// retirement, exactly as it did before any of this.
//
// And a refusal is permanent in the other direction too. Measured on the lab: the Edge came up before the
// control plane finished restarting, the older binary answered HTTP 400 to a stream it did not know, and the
// shipper — correctly — set those records aside rather than retrying a refusal forever. Three facts went to
// the refused spool and nothing would have re-sent them for weeks.
//
// Retirement requires observations newer than the rotation and less than five
// minutes old. Re-send within that window even when a certificate has not changed
// (for example a BYO device during a managed CA rotation). Preserve LastSeenAt:
// replaying an offline device must never manufacture a fresh handshake.
const deviceCertificateReshipEvery = time.Minute

// reshipDeviceCertificateFacts re-sends every fact this node holds. Idempotent by construction — the receiver
// keeps the newer observation — so a re-ship can never move the fleet's view backwards.
func reshipDeviceCertificateFacts() {
	if deviceCertificateShipWriter.Load() == nil {
		return
	}
	for _, fact := range deviceCertificates.snapshot() {
		shipDeviceCertificateFact(fact)
	}
}

// startDeviceCertificateReship runs the re-ship for as long as the process does. Started only where shipping is
// armed, so a node with no control plane does no work.
func startDeviceCertificateReship() {
	go func() {
		// ★ AND ONCE SHORTLY AFTER START, because the window right after a restart is the dangerous one and
		// waiting half an hour for the first re-ship leaves it open for exactly that long. Long enough that
		// devices have reconnected and this node has something to say; short enough that an operator who
		// restarted the control plane and went to withdraw a CA is not told to come back later.
		time.Sleep(deviceCertificateReshipEvery)
		reshipDeviceCertificateFacts()
		for range time.Tick(deviceCertificateReshipEvery) {
			reshipDeviceCertificateFacts()
		}
	}()
}

// recordShippedDeviceCertificateFact folds a shipped fact into this process's view. Runs on the control plane,
// which is where the fleet's view has to exist for the withdrawal gate to read it.
//
// Best-effort and silent on anything that is not one, exactly like the folds beside it: this path carries every
// shipped record in the deployment, and refusing a batch because one record did not parse would lose the rest.
func recordShippedDeviceCertificateFact(stream string, body []byte) {
	if stream != deviceCertificateFactStream {
		return
	}
	var fact deviceCertificateFact
	if json.Unmarshal(body, &fact) != nil || fact.Identity == "" {
		return
	}
	deviceCertificates.adopt(fact)
}
