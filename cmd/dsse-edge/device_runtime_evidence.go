package main

import (
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// Presence is not an observation of every runtime field. In particular, a
// version heartbeat can reach a different Edge from the posture report or mux.
// Carry the original observation clocks so that sparse/cached snapshots do not
// erase, refresh, or resurrect evidence supplied by another Edge.
type runtimeObservationTimes map[string]string

var runtimeObservationFields = [...]string{"os", "users", "disk_encryption_enabled", "firewall_enabled", "enforcement_agent_healthy", "steering", "source_ip"}

func runtimeTime(s string) time.Time {
	at, _ := time.Parse(time.RFC3339Nano, s)
	return at
}

func (times runtimeObservationTimes) clone() runtimeObservationTimes {
	copy := make(runtimeObservationTimes, len(times))
	for _, field := range runtimeObservationFields {
		if at := times[field]; at != "" {
			copy[field] = at
		}
	}
	return copy
}

func (e *deviceRuntimeInfo) observed(field string, at time.Time) {
	if e.observedAt == nil {
		e.observedAt = runtimeObservationTimes{}
	}
	e.observedAt[field] = at.UTC().Format(time.RFC3339Nano)
}

func runtimeTimesFromRow(row map[string]any) runtimeObservationTimes {
	result := runtimeObservationTimes{}
	value, present := row["runtime_observed_at"]
	if !present {
		value, present = row["observed_at"] // compact API view used by hydration
	}
	if present {
		for _, field := range runtimeObservationFields {
			var raw string
			switch v := value.(type) {
			case runtimeObservationTimes:
				raw = v[field]
			case map[string]string:
				raw = v[field]
			case map[string]any:
				raw, _ = v[field].(string)
			}
			if !runtimeTime(raw).IsZero() {
				result[field] = raw
			}
		}
		return result
	}
	// Older state rows are complete snapshots. An explicitly empty field in
	// those rows remains an update, rather than being silently filled forever.
	stamp := stringFromRow(row, "timestamp")
	for group, fields := range map[string][]string{
		"os": {"os"}, "users": {"logged_in_users", "auth_accounts"},
		"disk_encryption_enabled":   {"disk_encryption_enabled", "posture"},
		"firewall_enabled":          {"firewall_enabled", "posture"},
		"enforcement_agent_healthy": {"enforcement_agent_healthy", "posture"},
		"steering":                  {"last_steered"}, "source_ip": {"source_ip"},
	} {
		for _, field := range fields {
			if _, exists := row[field]; exists {
				result[group] = stamp
				break
			}
		}
	}
	postureAt := stringFromRow(row, "posture_collected_at")
	if nested, ok := row["posture"].(map[string]any); ok {
		postureAt = firstNonEmptyString(nested["collected_at"], postureAt)
	}
	if at := postureAt; !runtimeTime(at).IsZero() {
		for _, field := range runtimePostureFields {
			if result[field] != "" {
				result[field] = at
			}
		}
	}
	if at := stringFromRow(row, "last_steered"); !runtimeTime(at).IsZero() {
		result["steering"] = at
	}
	return result
}

func runtimeTimesForView(view deviceRuntimeView) runtimeObservationTimes {
	if view.ObservedAt != nil {
		return view.ObservedAt
	}
	// Compatibility for an older compact view: an absent value cannot assert a
	// clear without an observation clock. Current producers always carry one.
	result := runtimeObservationTimes{}
	if view.OS != "" {
		result["os"] = view.LastSeen
	}
	if len(view.LoggedInUsers) != 0 {
		result["users"] = view.LastSeen
	}
	if view.SourceIP != "" {
		result["source_ip"] = view.LastSeen
	}
	if view.Posture.CollectedAt != "" {
		for _, field := range runtimePostureFields {
			result[field] = view.Posture.CollectedAt
		}
	}
	if view.LastSteered != "" {
		result["steering"] = view.LastSteered
	} else if view.SteerActive {
		result["steering"] = view.LastSeen
	}
	return result
}

// Merge only newer observations, including explicit empty/false values. The
// caller has already scoped both views to the same tenant and ledger identity.
// This does not extend the steering window or change posture collection time.
func mergeRuntimeViews(held, incoming deviceRuntimeView) deviceRuntimeView {
	times := runtimeTimesForView(held).clone()
	for field, raw := range runtimeTimesForView(incoming) {
		at := runtimeTime(raw)
		if at.IsZero() || !at.After(runtimeTime(times[field])) {
			continue
		}
		// A legacy local view without a clock is not evidence that a shipped
		// value is newer. Keep its known facts; sparse current views carry {}.
		if held.ObservedAt == nil && runtimeTime(times[field]).IsZero() &&
			((field == "os" && held.OS != "") || (field == "users" && len(held.LoggedInUsers) > 0) ||
				(field == "steering" && held.SteerActive)) {
			continue
		}
		times[field] = raw
		switch field {
		case "os":
			held.OS = incoming.OS
		case "users":
			held.LoggedInUsers = incoming.LoggedInUsers
		case "disk_encryption_enabled":
			held.Posture.DiskEncryptionEnabled = incoming.Posture.DiskEncryptionEnabled
		case "firewall_enabled":
			held.Posture.FirewallEnabled = incoming.Posture.FirewallEnabled
		case "enforcement_agent_healthy":
			held.Posture.EnforcementAgentHealthy = incoming.Posture.EnforcementAgentHealthy
		case "steering":
			held.LastSteered, held.SteerActive, held.Edge = incoming.LastSteered, incoming.SteerActive, incoming.Edge
		case "source_ip":
			held.SourceIP = incoming.SourceIP
		}

		for _, postureField := range runtimePostureFields {
			if field == postureField {
				if held.Posture.Source == "" || held.Posture.Source == incoming.Posture.Source {
					held.Posture.Source = incoming.Posture.Source
				} else {
					held.Posture.Source = "mixed_runtime_observations"
				}
			}
		}
	}
	if runtimeTime(incoming.LastSeen).After(runtimeTime(held.LastSeen)) {
		held.LastSeen = incoming.LastSeen
	}
	held.ObservedAt = times
	held.Posture.CollectedAt = postureCollectedAt(held.Posture, times)
	return held
}

var runtimePostureFields = [...]string{"disk_encryption_enabled", "firewall_enabled", "enforcement_agent_healthy"}

func postureCollectedAt(posture model.DevicePostureSignals, times runtimeObservationTimes) string {
	// One compact collection time cannot claim that every retained signal is
	// as fresh as the newest partial report. Keep the oldest present signal.
	var oldest time.Time
	for field, value := range map[string]*bool{
		"disk_encryption_enabled":   posture.DiskEncryptionEnabled,
		"firewall_enabled":          posture.FirewallEnabled,
		"enforcement_agent_healthy": posture.EnforcementAgentHealthy,
	} {
		at := runtimeTime(times[field])
		if value != nil && !at.IsZero() && (oldest.IsZero() || at.Before(oldest)) {
			oldest = at
		}
	}
	if oldest.IsZero() {
		return ""
	}
	return oldest.UTC().Format(time.RFC3339Nano)
}
