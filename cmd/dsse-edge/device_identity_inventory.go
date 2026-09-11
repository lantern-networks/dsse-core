package main

import (
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
)

// Admission identities are case-insensitive. Old runtime rows retain the certificate's
// spelling, while the enrollment ledger uses NormalizeIdentity. Join within a tenant
// and retain the latest liveness plus the latest non-empty reported version.
func runtimeDevicesByIdentity(devices []model.Device, tenantID string) map[string]model.Device {
	rows := append([]model.Device(nil), devices...)
	sort.Slice(rows, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339Nano, rows[i].LastSeenAt)
		b, _ := time.Parse(time.RFC3339Nano, rows[j].LastSeenAt)
		if a.Equal(b) {
			return rows[i].ID < rows[j].ID
		}
		return a.Before(b)
	})
	out := map[string]model.Device{}
	for _, row := range rows {
		if strings.TrimSpace(row.TenantID) == "" || row.TenantID != tenantID {
			continue
		}
		id := enrolledinventory.NormalizeIdentity(row.ID)
		if id == "" {
			continue
		}
		if old, ok := out[id]; ok {
			if row.AgentVersion == "" {
				row.AgentVersion = old.AgentVersion
			}
			if row.OS == "" {
				row.OS = old.OS
			}
		}
		row.ID = id
		out[id] = row
	}
	return out
}

func updateEventsByIdentity(events map[string]model.AgentUpdateEvent) map[string]model.AgentUpdateEvent {
	out := map[string]model.AgentUpdateEvent{}
	for id, event := range events {
		key := enrolledinventory.NormalizeIdentity(id)
		old, exists := out[key]
		at, _ := time.Parse(time.RFC3339Nano, event.Timestamp)
		prior, _ := time.Parse(time.RFC3339Nano, old.Timestamp)
		if !exists || at.After(prior) || (at.Equal(prior) && event.ID > old.ID) {
			event.DeviceID = key
			out[key] = event
		}
	}
	return out
}
