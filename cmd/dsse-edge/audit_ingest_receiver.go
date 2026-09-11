package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"sync"

	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// Audit-ingest receiver (control plane side): receives audit/event records SHIPPED by enforcement Edges
// (the best-effort shipper in audit_ship.go) and appends them to the control plane's own log streams — which
// the postgres hot-store mirror persists to Postgres. This closes the decoupling loop: Edge emits + ships →
// control plane receives + persists (Postgres) → Console queries it. Bearer-authenticated; only the known
// audit/access streams are accepted. Registered only when a receiver token is configured (control plane).
// warnAuditIngestUnverifiedOnce says, exactly once, that the tenant binding cannot be enforced here. Once
// because this is a per-record path and a line per record would be its own outage.
var auditIngestUnverifiedWarned sync.Once

func warnAuditIngestUnverifiedOnce() {
	auditIngestUnverifiedWarned.Do(func() {
		log.Printf("★ audit-ingest: shipments arrive with NO verified client certificate, so the tenant on each " +
			"record cannot be checked against the edge that sent it. The shared bearer is then the only control: " +
			"anything holding it can write any tenant's audit history and fleet numbers. Terminate this endpoint " +
			"with client certificates (the operator-TLS anchors) to close it")
	})
}

func registerAuditIngestReceiver(mux *http.ServeMux, writer *logs.Writer, token string,
	agentTelemetry agenttelemetry.RuntimeStore, observedExclusions observedExclusionStoreAPI,
	tenantCARegistry *tenantca.TenantCARegistry, devMode bool) {
	token = strings.TrimSpace(token)
	if token == "" || writer == nil {
		return
	}
	allowed := map[string]bool{}
	for _, s := range defaultAuditShipStreams {
		allowed[s] = true
	}
	mux.HandleFunc("POST /audit-ingest", func(w http.ResponseWriter, r *http.Request) {
		if !auditIngestBearerValid(r, token) {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("audit-ingest: unauthorized"))
			return
		}
		// ★ WHICH EDGE IS THIS, AND MAY IT SPEAK FOR THAT TENANT (2026-08-12, ninth review). The bearer is
		// shared by every Edge in the deployment and nothing checked the tenant on the record — so one
		// compromised Edge, or the token alone, could forge audit history, ClickHouse rows and (since the fleet
		// view is now fed from here) the numbers an operator makes rollout decisions from.
		//
		// The shipper reaches this over the operator-TLS anchors, so the sending Edge presents a certificate:
		// its tenant is derived from WHICH registered Tenant CA that certificate chains to, exactly as the data
		// plane does it, and a record naming a different tenant is refused. Where no certificate is presented
		// (the lab's plaintext listener) the check cannot run and says so once, rather than pretending.
		// ★ FAIL CLOSED, NOT WARN (2026-08-12, tenth review). Continuing on "cannot verify" meant the binding
		// never engaged on the real path — the shipper presented no certificate at all — so the shared bearer
		// was the only control while the code read as if it were not. A check that always takes its lenient
		// branch is worse than no check.
		//
		// devMode still passes, because the lab's plaintext listener presents nothing and requiring a
		// certificate there would mean the lab cannot exercise this path. Everywhere else a shipment that
		// cannot be attributed to an Edge is refused, and the refusal names what to configure.
		shipper, verified := auditIngestShipperFrom(r, tenantCARegistry)
		if !verified && !devMode {
			warnAuditIngestUnverifiedOnce()
			writeError(w, http.StatusUnauthorized, fmt.Errorf("audit-ingest: this shipment carries no verified "+
				"client certificate, so the tenant on its records cannot be bound to the edge that sent them. "+
				"Configure -audit-ingest-client-cert/-key on the edge and terminate this endpoint with the "+
				"operator-TLS anchors"))
			return
		}
		stream := strings.TrimSpace(r.Header.Get("x-audit-stream"))
		if !allowed[stream] {
			writeError(w, http.StatusBadRequest, fmt.Errorf("audit-ingest: unknown stream %q", stream))
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxEdgeRuntimeJSONBodyBytes))
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("audit-ingest: read body: %w", err))
			return
		}
		var probe any
		if json.Unmarshal(body, &probe) != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("audit-ingest: body is not valid JSON"))
			return
		}
		if verified {
			// ★ AN EMPTY TENANT WAS A WAY PAST THE CHECK (2026-08-12, twelfth review). The comparison was
			// skipped when the record claimed no tenant, and nothing required the body to be an object at all —
			// so an Edge holding a valid certificate could write arbitrary tenant-less JSON into the `_system`
			// partition, which is the one place a record belongs to nobody and everybody reads.
			//
			// A verified shipment must name a tenant, and it must be the one its certificate proves.
			var claimed map[string]any
			if json.Unmarshal(body, &claimed) != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("audit-ingest: a shipped record must be a JSON "+
					"object naming the tenant it belongs to"))
				return
			}
			want := strings.TrimSpace(stringValue(claimed["tenant_id"]))
			if want == "" {
				writeError(w, http.StatusForbidden, fmt.Errorf("audit-ingest: this record names no tenant, and a "+
					"shipment from an identified edge cannot be filed under none"))
				return
			}
			if !edgeMayShipForTenant(shipper, want) {
				writeError(w, http.StatusForbidden, fmt.Errorf("audit-ingest: %s is not authorised to ship "+
					"records for tenant %q. A control plane serving several tenants needs an edge→tenants map "+
					"(-audit-ingest-authority); with none, an edge may ship only for the tenant its certificate "+
					"was issued by", shipper, want))
				return
			}
		}
		// Append the original record verbatim (RawMessage re-encodes as-is) -> local jsonl + postgres mirror.
		if err := writer.Append(stream, json.RawMessage(body)); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("audit-ingest: persist: %w", err))
			return
		}
		// ★ THE FLEET'S UPDATE PICTURE IS BUILT HERE, ONE EVENT AT A TIME (2026-08-12, and this is the SECOND
		// attempt — the first one read it back out of the hot store on every Console load).
		//
		// A device reports to its EDGE, so the Edge's in-process telemetry knows and the control plane's does
		// not: `GET /admin/agent-rollout` answered total=1 on the Edge and total=0 on the CP, which is the
		// number an operator actually sees. The records themselves DO arrive here — that is what this handler
		// is — so the fix belongs at arrival.
		//
		// The first fix queried the hot store when the summary was asked for. Measured in the lab: an
		// unwindowed scan with a JSON filter took ClickHouse from idle to 340% CPU, made its own INGEST time
		// out, and then the control plane would not start because its hot-store health check timed out. Asking
		// what the fleet had installed took down the store the answer comes from. Recording on arrival is O(1)
		// per event and leaves the summary the cheap in-memory read it already was.
		recordShippedAgentUpdate(r.Context(), agentTelemetry, stream, body)
		// A device's own report of what it is applying, folded into THIS node's observed-exclusion store — on
		// the control plane, that is the deployment's durable copy. See observed_exclusion_ship.go.
		recordShippedObservedExclusion(observedExclusions, stream, body)
		// Which certificate a device is presenting, as an Edge saw it. The device-CA withdrawal gate reads this,
		// and a control plane observes no handshakes of its own — see device_certificate_fact_ship.go.
		recordShippedDeviceCertificateFact(stream, body)
		// ★ AND THE FLEET'S DEVICE PICTURE, for the same reason one comment up (2026-08-14). The fleet view used
		// to replay 48 hours of these rows per Console load; a steering device now re-ships once a minute, which
		// took that query to 10.7 seconds and pushed quiet devices out of a 2000-row cap. Folding here is O(1)
		// per event and bounded by the number of devices rather than by how much they steer.
		recordShippedDeviceState(fleetDeviceProjectionStore, stream, body)
		w.WriteHeader(http.StatusAccepted)
	})
}

// recordShippedAgentUpdate folds an update outcome shipped by an Edge into THIS process's fleet view.
//
// Best-effort and silent on anything that is not one: the ingest path carries every audit record in the
// deployment, and a control plane that refused a shipment because one record did not parse would lose the
// whole batch to protect a summary.
func recordShippedAgentUpdate(ctx context.Context, agentTelemetry agenttelemetry.RuntimeStore, stream string,
	body []byte) {
	if agentTelemetry == nil || stream != "audit.log.jsonl" {
		return
	}
	// ★ THE FIELD NAMES ARE THE BUILDER'S, NOT THE ONES I ASSUMED (2026-08-12, ninth review). This read
	// metadata.event_id and metadata.device_id; agentUpdateAuditLog writes metadata.agent_update_event_id and
	// puts the device in the TOP-LEVEL target_id. So in production every shipped outcome arrived with no id and
	// no device: Postgres rejected the row for a missing device while the receiver answered 202, and the memory
	// backend stored it with no id, so every re-ship counted again.
	//
	// It passed its test because the test hand-wrote the JSON it then asserted on — the same mistake the Swift
	// tests were corrected for this morning, repeated here in Go a few hours later. The test now builds the
	// record with agentUpdateAuditLog itself, so a change to the builder breaks the reader.
	var record struct {
		EventType string         `json:"event_type"`
		TenantID  string         `json:"tenant_id"`
		TargetID  string         `json:"target_id"`
		Timestamp string         `json:"timestamp"`
		Metadata  map[string]any `json:"metadata"`
	}
	if json.Unmarshal(body, &record) != nil || record.EventType != "agent_update_event_recorded" {
		return
	}
	// THE shared decoder — the same one startup hydration uses, so a record replayed after a restart decodes
	// identically to the live copy. Two decoders for one format is how the two disagreed.
	event := agentUpdateEventFromAuditMetadata(stringValue(record.Metadata["agent_update_event_id"]),
		record.TenantID, record.TargetID, record.Metadata)
	if event.Timestamp == "" {
		event.Timestamp = record.Timestamp
	}
	if event.ID == "" || event.DeviceID == "" {
		// Without both, the store cannot de-duplicate a replay and Postgres will not accept the row at all.
		// Refusing here is honest: the audit record IS stored, and the summary under-counts by one rather than
		// silently double-counting on every re-ship.
		log.Printf("audit-ingest: a shipped agent update carried no %s — it is stored as audit and NOT counted "+
			"in the fleet view", map[bool]string{true: "event id", false: "device"}[event.ID == ""])
		return
	}
	if err := agentTelemetry.RecordUpdate(ctx, event); err != nil {
		log.Printf("audit-ingest: an update outcome shipped for device %s could not be recorded in the fleet "+
			"view (%v) — the audit record IS stored; the summary will under-count", event.DeviceID, err)
	}
}

func auditIngestBearerValid(r *http.Request, token string) bool {
	auth := strings.TrimSpace(r.Header.Get("authorization"))
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return false
	}
	presented := strings.TrimSpace(auth[len("Bearer "):])
	return presented != "" && subtle.ConstantTimeCompare([]byte(presented), []byte(token)) == 1
}

// recordShippedDeviceState folds a shipped device_state row into this process's fleet projection.
//
// Best-effort and silent on anything that is not one, exactly like recordShippedAgentUpdate above: this path
// carries every audit record in the deployment, and a control plane that refused a shipment because one record
// did not parse would lose the whole batch to protect a summary.
func recordShippedDeviceState(p *fleetDeviceProjection, stream string, body []byte) {
	if p == nil || stream != "device_state.log.jsonl" {
		return
	}
	var row map[string]any
	if json.Unmarshal(body, &row) != nil {
		return
	}
	p.Fold(row)
}
