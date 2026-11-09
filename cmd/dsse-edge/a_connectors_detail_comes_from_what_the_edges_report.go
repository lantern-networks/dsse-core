package main

// a_connectors_detail_comes_from_what_the_edges_report.go — the control plane keeps what a connector says about
// itself and where its tunnel is, so the Console's detail stops reading "unknown".
//
// ★★ "TUNNEL unknown · VERSION unknown · UPTIME unknown" FOR A CONNECTOR CARRYING TRAFFIC (2026-11-08, acceptance
// C, third walk). The detail is read from the control plane, which holds no tunnels. The Edge that holds one
// reports the connector every half minute with the connector's own heartbeat in it — version, uptime — and the
// control plane took the heartbeat time and the status and dropped the rest. An operator following a connector
// through a failover could only find out where it was by logging in to the machine at the site.
//
// ★ RUNTIME, NOT ROUTE. These ride in the metadata and never move the catalog's version, for the reason
// AttachedRegionID does not: a connector's uptime changes on every report.

import (
	"log"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

// connectorReportObservedAt is when a report's facts were observed: the time the Edge made the report, else the
// heartbeat it carries, else now. Never later than now — a reporter's clock ahead of this one must not make a
// report outrank everything after it.
//
// ★ NOT THE TIME IT ARRIVED (review C3-R5). The first version stamped tunnel_reported_at with the receiving
// clock, so a report replayed from an Edge's outbox an hour later read as a tunnel seen a moment ago — the
// detail said "connected" about a connector that was gone — and an old report written over a newer one put back
// the old entrance, version and uptime.
func connectorReportObservedAt(queuedAt, heartbeatAt string, now time.Time) time.Time {
	for _, raw := range []string{queuedAt, heartbeatAt} {
		if at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw)); err == nil {
			if at.After(now) {
				return now
			}
			return at
		}
	}
	return now
}

// recordConnectorRuntime keeps the connector-reported version and uptime from a report, and, when the report is
// from the node holding the tunnel (region != ""), when and where that was said — all as of observed, and only
// when observed is not older than what is held. A store that cannot record it is said once per report rather
// than silently leaving the detail empty.
func recordConnectorRuntime(registry connectorRegistryStore, reg model.ConnectorRegistration, region string, observed time.Time) {
	rec, ok := registry.(connectorRuntimeRecorder)
	if !ok {
		log.Printf("connector_runtime_dropped connector=%q: this control plane's connector store cannot record "+
			"version, uptime or where the tunnel is, so the detail reads unknown", reg.ID)
		return
	}
	fields := map[string]any{}
	// The process facts are as old as the Edge's observation of them, not as the report (review C3-R5-1): a
	// tunnel report made now can carry a version the Edge last heard an hour ago, or one it took from an older
	// catalogue copy. The Edge stamps them (connector.HeartbeatRuntime); without its stamp, the report's time is
	// the best that is known.
	processAt := observed
	if at, ok := connectorRuntimeStampOf(reg.Metadata, connector.RuntimeObservedAtKey); ok && at.Before(observed) {
		processAt = at
	}
	if v := adminConnectorVersion(reg.Metadata); v != "" {
		fields["version"] = v
	}
	if up := adminConnectorUptimeSeconds(reg.Metadata); up != nil {
		fields["uptime_seconds"] = *up
	}
	if len(fields) > 0 {
		fields[connector.RuntimeObservedAtKey] = processAt.UTC().Format(time.RFC3339Nano)
	}
	if region = strings.TrimSpace(region); region != "" {
		fields["tunnel_reported_at"] = observed.UTC().Format(time.RFC3339Nano)
		fields["tunnel_region"] = region
	}
	if len(fields) == 0 {
		return
	}
	if _, err := rec.RecordRuntime(reg.TenantID, reg.ID, fields); err != nil {
		log.Printf("connector_runtime_dropped connector=%q: %v", reg.ID, err)
	}
}

// connectorTunnelReported answers "does an Edge hold this connector's tunnel" on a node that holds none, from
// the last report of the node that does. Only a recent report says yes; an old one is not evidence either way,
// so it stays unknown and the heartbeat decides whether the connector is online.
func connectorTunnelReported(metadata map[string]any, now time.Time) *bool {
	raw, _ := metadata["tunnel_reported_at"].(string)
	at, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	if at.Add(adminSiteHeartbeatFreshness).Before(now) {
		return nil
	}
	yes := true
	return &yes
}

// copyConnectorMetadata is a copy of a registration's metadata, so what a report said survives a Register that
// rewrites the map it was given.
func copyConnectorMetadata(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// connectorRuntimeFieldsOf is the runtime facts (connector.RuntimeKeys) a registration carries, as RecordRuntime
// takes them.
func connectorRuntimeFieldsOf(metadata map[string]any) map[string]any {
	out := map[string]any{}
	for k := range connector.RuntimeKeys {
		if v, ok := metadata[k]; ok && v != nil {
			out[k] = v
		}
	}
	return out
}

func connectorRuntimeStampOf(metadata map[string]any, key string) (time.Time, bool) {
	raw, _ := metadata[key].(string)
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	return at, err == nil
}
