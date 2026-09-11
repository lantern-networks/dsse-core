package main

// agent_update_fleet_summary.go — where the fleet's update picture is read from.
//
// In a sibling file rather than main.go because the decomposition ratchet says so, and it is right: this is a
// question with its own answer (WHICH store knows) and it does not belong in the file that wires everything.

import (
	"context"
	"fmt"
	"log"
	"strings"

	agenttelemetry "github.com/lantern-networks/dsse-core/agenttelemetry"
	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

// adminAgentUpdateEventSummary builds the fleet's update picture.
//
// ★ THE CONTROL PLANE HELD THE RECORDS AND ANSWERED ZERO (2026-08-12, found on hardware after the reporting
// lane finally worked end to end). A device reports to its EDGE, and the Edge's telemetry store is in-process:
// so `GET /admin/agent-rollout` on the Edge said total=1 installed=1 while the same call on the CONTROL PLANE
// — which is what the Console reads, and therefore what an operator sees — said total=0.
//
// The data was already there. The audit shipper carries `agent_update_event_recorded` to the CP's hot store
// (verified in the lab: the record landed in ClickHouse at the second the device's report was delivered), and
// this function was reading the process's OWN in-memory store instead. Same shape as the defect it completes:
// the report reached a place nobody was looking at.
//
// So a process that HAS a hot store answers from it — that is the aggregated, fleet-wide, restart-safe view,
// exactly the reasoning already written for inspection_events in audit_ship.go. The in-process store is the
// fallback for an Edge with no hot store, where it is the only thing that knows.
func adminAgentUpdateEventSummary(writer *logs.Writer, agentTelemetry agenttelemetry.RuntimeStore, tenantID string) (map[string]any, error) {
	return adminAgentUpdateEventSummaryFrom(nil, writer, agentTelemetry, tenantID)
}

func adminAgentUpdateEventSummaryFrom(hot hotstore.Store, writer *logs.Writer,
	agentTelemetry agenttelemetry.RuntimeStore, tenantID string) (map[string]any, error) {
	// ★ NOT A QUERY, AND THIS IS THE SECOND ATTEMPT. The fleet view is fed at INGEST — a control plane records
	// each shipped outcome as it arrives (recordShippedAgentUpdate) — so this stays the cheap in-memory read it
	// always was.
	//
	// The first attempt scanned the hot store here instead, and the lab measured what that costs: an unwindowed
	// scan with a JSON filter took ClickHouse from idle to 340% CPU, made its own INGEST time out, and then the
	// control plane would not start at all because its hot-store health check timed out. Asking what the fleet
	// had installed took down the store the answer came from.
	_ = hot
	if agentTelemetry != nil {
		summary, err := agentTelemetry.UpdateSummary(context.Background(), tenantID)
		if err != nil {
			return nil, err
		}
		// ★ AND THE FALLBACK ONLY HELD WHILE THE STORE WAS EMPTY (2026-08-12, tenth review). The first fix used
		// the log when the in-memory summary was zero — so the FIRST shipment after a restart made it non-zero
		// and every pre-restart outcome disappeared behind that one event. A fleet view that loses its history
		// on the first new arrival is worse than one that is honestly empty, because it looks populated.
		//
		// The store is HYDRATED FROM THE LOG AT STARTUP instead (see hydrateAgentUpdateTelemetry), so there is
		// no window in which the two disagree, and this stays the cheap in-memory read it always was. The log
		// fallback remains for a process with no store at all.
		return summary, nil
	}
	return agentUpdateSummaryFromLog(writer, tenantID)
}

// hydrateAgentUpdateTelemetry loads the canonical log into the runtime store at STARTUP.
//
// ★ THE STORE DEFAULTS TO MEMORY, so a control plane restart used to reset the fleet's update history to zero
// — and the reference deployment configures no durable backend, which makes that the normal case rather than
// an edge one. The records were never lost: they are in the append-only jsonl this process wrote. Reading them
// once at startup is what makes the runtime store agree with the durable one, instead of the read path having
// to reconcile two sources on every request.
//
// Best-effort: a control plane that cannot read its own log still starts and still records what arrives from
// here on. It says what it could not recover rather than presenting a partial history as a complete one.
// ★ EVERY TENANT, NOT THE DEFAULT ONE (2026-08-12, eleventh review). It was hydrated for
// evaluator.PolicyBundle.TenantID alone while the admin API answers for whichever tenant the caller operates
// within — so on a multi-tenant control plane every OTHER tenant's history still vanished on restart, which is
// the failure this function was added to remove, narrowed rather than fixed.
//
// And it read the whole log to keep one tenant's rows. One pass now, keyed by the tenant on each record, which
// is both correct and cheaper than the version that was only correct for one of them.
func hydrateAgentUpdateTelemetry(store agenttelemetry.RuntimeStore, writer *logs.Writer) {
	if store == nil || writer == nil {
		return
	}
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		log.Printf("★ fleet update history could NOT be recovered from the log (%v): this control plane starts "+
			"with an empty picture and will only show outcomes shipped from now on", err)
		return
	}
	seen := map[string]bool{}
	recovered, tenants := 0, map[string]bool{}
	for _, row := range rows {
		if stringValue(row["event_type"]) != "agent_update_event_recorded" {
			continue
		}
		event, key, ok := agentUpdateEventFromAuditRow(row, stringValue(row["tenant_id"]))
		if !ok || seen[key] {
			continue
		}
		seen[key] = true
		if rerr := store.RecordUpdate(context.Background(), event); rerr == nil {
			recovered++
			tenants[event.TenantID] = true
		}
	}
	if recovered > 0 {
		log.Printf("fleet update history: recovered %d outcome(s) across %d tenant(s) from the canonical log",
			recovered, len(tenants))
	}
}

// agentUpdateSummaryFromLog rebuilds the picture from the canonical append-only log.
//
// The field names are the audit BUILDER's — metadata.agent_update_event_id and the top-level target_id — and
// they are read here for the same reason the ingest receiver reads them: assuming them cost a release's worth
// of shipped outcomes once already.
func agentUpdateSummaryFromLog(writer *logs.Writer, tenantID string) (map[string]any, error) {
	events, err := agentUpdateEventsFromLog(writer, tenantID)
	if err != nil {
		return nil, err
	}
	return agenttelemetry.UpdateSummaryFromEvents(events), nil
}

// agentUpdateEventsFromLog reads the outcomes this process has recorded, de-duplicated by (device, event id).
//
// The field names are the audit BUILDER's — metadata.agent_update_event_id and the top-level target_id — and
// they are read here for the same reason the ingest receiver reads them: assuming them cost a release's worth
// of shipped outcomes once already.
func agentUpdateEventsFromLog(writer *logs.Writer, tenantID string) ([]model.AgentUpdateEvent, error) {
	if writer == nil {
		return nil, fmt.Errorf("no log to rebuild the fleet view from")
	}
	rows, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	events := []model.AgentUpdateEvent{}
	for _, row := range rows {
		if stringValue(row["tenant_id"]) != tenantID || stringValue(row["event_type"]) != "agent_update_event_recorded" {
			continue
		}
		event, key, ok := agentUpdateEventFromAuditRow(row, tenantID)
		if !ok || seen[key] {
			continue
		}
		seen[key] = true
		events = append(events, event)
	}
	return events, nil
}

// agentUpdateEventFromAuditRow reads ONE shipped record. The field names are the audit BUILDER's — assuming
// them once already cost a release's worth of outcomes — and the key is (device, event id), because the id is
// chosen by the endpoint and means nothing without the device beside it.
func agentUpdateEventFromAuditRow(row map[string]any, tenantID string) (model.AgentUpdateEvent, string, bool) {
	metadata, _ := row["metadata"].(map[string]any)
	device := stringValue(row["target_id"])
	id := stringValue(metadata["agent_update_event_id"])
	if strings.TrimSpace(tenantID) == "" || device == "" || id == "" {
		return model.AgentUpdateEvent{}, "", false
	}
	// ★ ONE DECODER FOR BOTH PATHS (2026-08-12, twelfth review). The live receiver restores the failure
	// reason, the checksum/signature and the device's own metadata; this one dropped them — so after a restart
	// the hydrated copy and a re-shipped live copy of the SAME record differed, and the newly strict
	// same-payload check rejected the live one as "a different event with the same id". Two decoders for one
	// format is the same class as the two derivations of a key id, and it arrives the same way.
	return agentUpdateEventFromAuditMetadata(id, tenantID, device, metadata),
		strings.ToLower(tenantID) + "\x00" + device + "\x00" + id, true
}

// agentUpdateEventFromAuditMetadata is THE decoder for a shipped agent-update audit record. The ingest
// receiver and the startup hydration both call it, so a field added to one is added to both.
func agentUpdateEventFromAuditMetadata(id, tenantID, device string, metadata map[string]any) model.AgentUpdateEvent {
	event := model.AgentUpdateEvent{
		ID:                  id,
		TenantID:            tenantID,
		DeviceID:            device,
		CurrentAgentVersion: stringValue(metadata["current_agent_version"]),
		TargetAgentVersion:  stringValue(metadata["target_agent_version"]),
		ReleaseChannel:      stringValue(metadata["release_channel"]),
		UpdateStatus:        strings.TrimSpace(stringValue(metadata["update_status"])),
		UpdateSource:        stringValue(metadata["update_source"]),
		// Restored, because the in-memory store's same-event comparison reads it: without this a hydrated copy
		// and a live retry of the SAME report differ, and the retry is refused for ever.
		UserID:    stringValue(metadata["user_id"]),
		Timestamp: stringValue(metadata["event_timestamp"]),
	}
	if reason := stringValue(metadata["failure_reason"]); reason != "" {
		event.FailureReason = &reason
	}
	if checksum := stringValue(metadata["package_checksum"]); checksum != "" {
		event.PackageChecksum = &checksum
	}
	if signature := stringValue(metadata["package_signature"]); signature != "" {
		event.PackageSignature = &signature
	}
	if deviceMeta, ok := metadata["device_metadata"].(map[string]any); ok {
		event.Metadata = deviceMeta
	}
	return event
}
