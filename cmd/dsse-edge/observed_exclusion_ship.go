package main

import (
	"encoding/json"

	"github.com/lantern-networks/dsse-core/logs"
)

// observed_exclusion_ship.go — sending each device's report to the control plane instead of writing it to a
// database from the Edge.
//
// ★★★ WHY (2026-08-23). This is reverse telemetry: a device tells the Edge it reached which exclusions it is
// actually applying, which trust anchors it holds, which refusals it journalled. It is RUNTIME INFORMATION and
// an Edge is entitled to hold it — but the Edge was writing it straight into Postgres, which is one of the six
// reasons every enforcement node holds a database connection.
//
// The shape already exists in this tree and its own header states the rule: "The Edge owns no database; the
// control plane owns Postgres persistence. Shipping NEVER blocks enforcement." The audit shipper carries
// streams to the control plane's /audit-ingest, retains un-acked records in a bounded spool across a CP
// outage, replays them on recovery, and is idempotent on the receiving side. Device reports go the same way.
//
// ★ AND THE EDGE KEEPS ITS OWN VIEW. The in-memory store stays: an Edge answers admin questions about the
// devices it is serving without a round trip, and losing it on restart is recoverable — the next report
// repopulates it, which is exactly what the flag's own text says about "memory". What changes is that the
// DURABLE copy lives where durable copies live.
//
// ★★ THE EDGE'S VIEW IS ITS OWN, AND THAT IS A LIMIT WORTH KNOWING. A readiness question — "which enrolled
// devices already hold the CA about to be deployed" — answered from one Edge's memory is answered about the
// devices that reported to THAT Edge. The fleet's answer is the control plane's to give. That is the same gap
// as the device-CA withdrawal gate, and it is filed with it rather than papered over here.
//
// ★ WHY A SEPARATE STREAM. Folding these into device_state would mix two things a receiver has to tell apart:
// device_state is a posture projection, and this is the device's own account of its configuration. A receiver
// that had to guess which shape a row was would guess wrong on the day one of them gained a field.

// observedExclusionShipStream is the log stream device reports travel on. Named like the others so an operator
// reading a spool directory can tell what is in it.
const observedExclusionShipStream = "observed_exclusions.log.jsonl"

// shipObservedExclusion writes one device report to the shipped stream. Best-effort by construction: the
// writer appends locally and the shipper carries it, and neither may delay the response to a device that is
// only reporting. A report that cannot be written is lost rather than retried inline — the device sends
// another within the minute, which is why this telemetry is safe to treat that way and enforcement is not.
func shipObservedExclusion(writer *logs.Writer, entry observedExclusionEntry) {
	if writer == nil {
		return
	}
	row, err := json.Marshal(entry)
	if err != nil {
		return
	}
	var fields map[string]any
	if json.Unmarshal(row, &fields) != nil {
		return
	}
	// The stream name is carried in the record too, because the receiver is handed the stream separately and
	// a record that cannot say what it is becomes unattributable the moment anything re-batches it.
	fields["kind"] = "observed_exclusion_report"
	_ = writer.Append(observedExclusionShipStream, fields)
}

// recordShippedObservedExclusion folds a shipped report into this process's observed-exclusion store. Runs on
// the control plane, where the durable copy lives.
//
// Best-effort and silent on anything that is not one, exactly like the device-state and agent-update folds
// beside it: this path carries every shipped record in the deployment, and a control plane that refused a
// shipment because one record did not parse would lose the whole batch to protect a summary.
func recordShippedObservedExclusion(store observedExclusionStoreAPI, stream string, body []byte) {
	if store == nil || stream != observedExclusionShipStream {
		return
	}
	var entry observedExclusionEntry
	if json.Unmarshal(body, &entry) != nil {
		return
	}
	if entry.TenantID == "" || entry.DeviceIdentity == "" {
		// A report that names neither an organization nor a device cannot be filed against anything, and
		// storing it would put a row in the durable copy that no screen can ever show.
		return
	}
	store.Record(entry)
}
