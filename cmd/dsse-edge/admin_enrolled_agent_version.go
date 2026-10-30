package main

import (
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

type fleetAgentVersionReport struct {
	Version    string
	ReportedAt string
}

// The enrollment ledger belongs to the control plane, but endpoint heartbeats
// reach an Edge. Only a tenant-matched, verified-device shipment may supply
// the version shown alongside that ledger entry.
func fleetAgentVersionsByIdentity(p *fleetDeviceProjection, tenant string) map[string]fleetAgentVersionReport {
	rows, _ := p.Devices(tenant)
	out := make(map[string]fleetAgentVersionReport, len(rows))
	for _, row := range rows {
		if row.TenantID != tenant || row.AgentVersion == "" || row.AgentVersionReportedAt == "" {
			continue
		}
		identity := enrolledinventory.NormalizeIdentity(row.DeviceID)
		if identity == "" {
			continue
		}
		reportedAt := strings.TrimSpace(row.AgentVersionReportedAt)
		if _, err := time.Parse(time.RFC3339Nano, reportedAt); err != nil {
			continue
		}
		if prior, ok := out[identity]; !ok || newerVersionReport(reportedAt, prior.ReportedAt) {
			out[identity] = fleetAgentVersionReport{Version: row.AgentVersion, ReportedAt: reportedAt}
		}
	}
	return out
}

func newerVersionReport(candidate, current string) bool {
	newAt, err := time.Parse(time.RFC3339Nano, candidate)
	if err != nil {
		return false
	}
	oldAt, err := time.Parse(time.RFC3339Nano, current)
	return err != nil || newAt.After(oldAt)
}
