package agenttelemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// RuntimeStore records agent update + status telemetry and reports per-tenant rollout/health summaries. The
// in-memory Store below is the default; a durable backing implements the same interface.
type RuntimeStore interface {
	RecordUpdate(context.Context, model.AgentUpdateEvent) error
	RecordStatus(context.Context, model.AgentStatus) error
	UpdateSummary(context.Context, string) (map[string]any, error)
	StatusSummary(context.Context, string) (map[string]any, error)
	// LatestUpdateByDevice is the most recent outcome each device reported, keyed by device id.
	//
	// ★ THE FLEET NUMBER WAS NEVER THE QUESTION AN OPERATOR ASKS (2026-08-12). "42 installed" tells nobody
	// WHICH machine is still on the old build, which one refused, or why — and the answer to those is the same
	// data, grouped differently. A summary that cannot be opened is a number to be believed rather than acted
	// on.
	LatestUpdateByDevice(context.Context, string) (map[string]model.AgentUpdateEvent, error)
}

type Store struct {
	mu      sync.RWMutex
	updates []model.AgentUpdateEvent
	status  []model.AgentStatus
}

func NewStore() *Store {
	return &Store{}
}

// RecordUpdate stores an update outcome, IDEMPOTENTLY on its id.
//
// ★ THE SAME EVENT ARRIVES MORE THAN ONCE IN ORDINARY OPERATION (2026-08-12). Two paths deliver it: a device
// whose report was accepted but whose response was lost retries, and the Edge→CP audit shipper RETAINS and
// REPLAYS un-acked records across a control-plane outage — that is its documented behaviour, not a failure.
// Appending blindly counted a replayed shipment as a second install, so a CP outage INFLATED the fleet's
// success numbers afterwards.
//
// The Postgres backend has always upserted on the event id; this one appended. Two implementations of one
// interface disagreeing about whether an id means anything is the kind of difference that only shows up in the
// deployment that uses the other one.
//
// An event with no id cannot be de-duplicated and is appended: two events with no id are two events.
func (store *Store) RecordUpdate(_ context.Context, event model.AgentUpdateEvent) error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	// ★ THE KEY IS (TENANT, DEVICE, EVENT), NOT THE ID ALONE (2026-08-12, ninth review). The id is chosen by
	// the ENDPOINT, so keyed on the id by itself one device could overwrite another's outcome — across tenants
	// — by picking the same string. The Postgres backend was re-keyed for exactly this an hour earlier and this
	// one, which is the DEFAULT backend, kept the hole.
	//
	// And a repeat with the SAME key but DIFFERENT contents is refused rather than applied: a retry re-sends
	// what it sent, so a payload that differs is not a retry, and letting it overwrite would make the store
	// answer with whichever copy arrived last.
	if key := agentUpdateEventKey(event); key != "" {
		for i, existing := range store.updates {
			if agentUpdateEventKey(existing) != key {
				continue
			}
			if !sameAgentUpdateEvent(existing, event) {
				return fmt.Errorf("agenttelemetry: %s already holds a DIFFERENT outcome for device %s in tenant "+
					"%s: refusing to overwrite it", event.ID, event.DeviceID, event.TenantID)
			}
			store.updates[i] = event
			return nil
		}
	}
	store.updates = append(store.updates, event)
	return nil
}

// agentUpdateEventKey is the identity of an outcome. Empty when it cannot be established — two events with no
// id are two events, and collapsing them would lose one.
func agentUpdateEventKey(event model.AgentUpdateEvent) string {
	id := strings.TrimSpace(event.ID)
	if id == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(event.TenantID)) + "\x00" +
		strings.ToLower(strings.TrimSpace(event.DeviceID)) + "\x00" + id
}

// sameAgentUpdateEvent compares what a retry would repeat.
//
// ★ IT COMPARED FOUR FIELDS AND CLAIMED TO COMPARE THE EVENT (2026-08-12, tenth review). Channel, user,
// checksum, signature and failure reason were all invisible, so a genuinely different event with the same key
// was accepted as a retry and overwrote the stored one — while Postgres, given the same pair, keeps the first.
// Two backends disagreeing about which copy survives is the kind of difference that only shows up in the
// deployment running the other one.
//
// Enumerated rather than reflected, so adding a field to the model is a decision here rather than a silent
// change of meaning. TIMESTAMP IS DELIBERATELY EXCLUDED and is the only exclusion: the shipper replays the
// record it holds and a device re-reporting carries its own clock, so a differing timestamp is the normal
// shape of a retry rather than evidence of a different event.
func sameAgentUpdateEvent(a, b model.AgentUpdateEvent) bool {
	return a.UpdateStatus == b.UpdateStatus &&
		a.CurrentAgentVersion == b.CurrentAgentVersion &&
		a.TargetAgentVersion == b.TargetAgentVersion &&
		a.UpdateSource == b.UpdateSource &&
		a.ReleaseChannel == b.ReleaseChannel &&
		a.UserID == b.UserID &&
		samePointer(a.PackageChecksum, b.PackageChecksum) &&
		samePointer(a.PackageSignature, b.PackageSignature) &&
		samePointer(a.FailureReason, b.FailureReason) &&
		sameMetadata(a.Metadata, b.Metadata)
}

// sameMetadata compares the device's own evidence — which is where a refusal's rejected-manifest digest lives,
// so two refusals of DIFFERENT documents must not be collapsed as one retry.
func sameMetadata(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	// ★ nil AND {} ARE THE SAME EVIDENCE AND MARSHALLED DIFFERENTLY (2026-08-13, twenty-ninth review). The
	// length check passes (0 == 0) and then json.Marshal renders nil as "null" and an empty map as "{}", so
	// they compared UNEQUAL. Ingest forces Metadata={}, the audit builder writes the field only when it is
	// non-empty, and hydration leaves it nil — so after a control-plane restart a device's retry of the SAME
	// report was refused as "a DIFFERENT outcome", answered 500, and that device's whole queue jammed behind a
	// retry that can never succeed. The user_id fix one commit earlier closed this for the field beside it and
	// left this one open.
	//
	// Both are "the device sent no evidence". Comparing them as equal is the only reading that is true.
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	left, lerr := json.Marshal(a)
	right, rerr := json.Marshal(b)
	if lerr != nil || rerr != nil {
		return false // unrenderable metadata is not something to call equal
	}
	return string(left) == string(right)
}

func samePointer(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// LatestUpdateByDevice returns the newest outcome per device. "Newest" is by the event's own timestamp, and
// ties fall to the one recorded last — a device reporting two outcomes in one second is reporting a sequence,
// and the store's order is the only thing that knows which came second.
func (store *Store) LatestUpdateByDevice(_ context.Context, tenantID string) (map[string]model.AgentUpdateEvent, error) {
	if store == nil {
		return map[string]model.AgentUpdateEvent{}, nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	latest := map[string]model.AgentUpdateEvent{}
	for _, event := range store.updates {
		if !strings.EqualFold(strings.TrimSpace(event.TenantID), strings.TrimSpace(tenantID)) {
			continue
		}
		device := strings.TrimSpace(event.DeviceID)
		if device == "" {
			continue
		}
		// A TIE GOES TO THE ONE RECORDED LATER, which is what iterating in append order and using a strict `>`
		// does. It matters because report timestamps are second-precision, so two outcomes from the same tick
		// are a tie — and the Postgres store has to break it the same way or the two disagree about which
		// half of "failed, then rolled back" is current. Over there the tie-break is created_at, the server's
		// own receipt order; here it is the order they arrived in this slice, which is the same thing.
		// ★ COMPARED AS TIMES, NOT AS TEXT (2026-08-13, twenty-ninth review). RFC3339 sorts correctly only when
		// every value carries the same offset: "2026-08-13T09:00:00+09:00" is the same instant as
		// "2026-08-13T00:00:00Z" and sorts ABOVE it, so a device reporting local time kept whichever outcome
		// happened to have the larger string — 'failed' staying newest for ever is the shape that shows up.
		// Unparseable values fall back to the text comparison rather than being dropped.
		// ★★ THE TIE MUST STILL GO TO THE LATER ENTRY, AND THE FIRST VERSION OF THIS FIX INVERTED IT
		// (2026-08-13, thirtieth review). `!recordedAfter(event, held)` also skips when the two are EQUAL, so a
		// tie kept the earlier one — while the comment directly above went on claiming the arrival order still
		// decided it. RFC3339 is second-granular, so "failed" and "rolled_back" recorded in the same second made
		// `failed` the current state for ever, and disagreed with the Postgres store's created_at tie-break: the
		// drill-down/summary divergence this very fix was written to end, reintroduced by it.
		//
		// So the skip is now the strict one: keep what is held only when it is genuinely NEWER.
		if held, ok := latest[device]; ok && recordedAfter(held.Timestamp, event.Timestamp) {
			continue
		}
		latest[device] = event
	}
	return latest, nil
}

func (store *Store) RecordStatus(_ context.Context, status model.AgentStatus) error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.status = append(store.status, status)
	return nil
}

func (store *Store) UpdateSummary(_ context.Context, tenantID string) (map[string]any, error) {
	if store == nil {
		return UpdateSummaryFromEvents(nil), nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	events := make([]model.AgentUpdateEvent, 0, len(store.updates))
	for _, event := range store.updates {
		// ★ MATCHED THE WAY EVERYTHING ELSE HERE MATCHES (2026-08-13, twenty-ninth review). RecordUpdate and
		// LatestUpdateByDevice trim and fold case; the summaries compared exactly — so a tenant id differing
		// only in case or whitespace put devices in the drill-down and left the summary at total:0, which is a
		// symptom this product has chased before.
		if sameTenant(event.TenantID, tenantID) {
			events = append(events, event)
		}
	}
	return UpdateSummaryFromEvents(events), nil
}

func (store *Store) StatusSummary(_ context.Context, tenantID string) (map[string]any, error) {
	if store == nil {
		return StatusSummaryFromEvents(nil), nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	statuses := make([]model.AgentStatus, 0, len(store.status))
	for _, status := range store.status {
		if sameTenant(status.TenantID, tenantID) {
			statuses = append(statuses, status)
		}
	}
	return StatusSummaryFromEvents(statuses), nil
}

// UpdateSummaryFromEvents aggregates update events into a rollout summary (counts + success rate over
// terminal events). Exported so a durable store can reuse the identical aggregation.
func UpdateSummaryFromEvents(events []model.AgentUpdateEvent) map[string]any {
	statusCounts := map[string]int{}
	total := 0
	terminal := 0
	installed := 0
	for _, event := range events {
		status := strings.TrimSpace(event.UpdateStatus)
		if status == "" {
			status = "unknown"
		}
		statusCounts[status]++
		total++
		switch status {
		case "installed":
			terminal++
			installed++
		case "failed", "rolled_back":
			terminal++
		}
	}
	var successRate any
	if terminal > 0 {
		successRate = float64(installed) / float64(terminal)
	}
	return map[string]any{
		"total":               total,
		"status_counts":       statusCounts,
		"terminal_events":     terminal,
		"installed_events":    installed,
		"update_success_rate": successRate,
	}
}

// StatusSummaryFromEvents aggregates status events into a health summary (crash-free + steering success
// rates). Exported so a durable store can reuse the identical aggregation.
func StatusSummaryFromEvents(statuses []model.AgentStatus) map[string]any {
	statusCounts := map[string]int{}
	total := 0
	crashEvents := 0
	steeringAttempted := 0
	steeringSucceeded := 0
	steeringFailed := 0
	connectUnsupported := 0
	for _, event := range statuses {
		status := strings.TrimSpace(event.Status)
		if status == "" {
			status = "unknown"
		}
		statusCounts[status]++
		total++
		if intMetadataValue(event.Metadata, "crash_count", 0) > 0 {
			crashEvents++
		}
		steeringAttempted += intMetadataValue(event.Metadata, "steering_attempted", 0)
		steeringSucceeded += intMetadataValue(event.Metadata, "steering_succeeded", 0)
		steeringFailed += intMetadataValue(event.Metadata, "steering_failed", 0)
		connectUnsupported += intMetadataValue(event.Metadata, "connect_unsupported", 0)
	}
	var crashFreeRate any
	if total > 0 {
		crashFreeRate = float64(total-crashEvents) / float64(total)
	}
	var steeringSuccessRate any
	if steeringAttempted > 0 {
		steeringSuccessRate = float64(steeringSucceeded) / float64(steeringAttempted)
	}
	return map[string]any{
		"total":                 total,
		"status_counts":         statusCounts,
		"crash_events":          crashEvents,
		"crash_free_rate":       crashFreeRate,
		"steering_attempted":    steeringAttempted,
		"steering_succeeded":    steeringSucceeded,
		"steering_failed":       steeringFailed,
		"connect_unsupported":   connectUnsupported,
		"steering_success_rate": steeringSuccessRate,
	}
}

// intMetadataValue reads an int-ish metadata value (int/float64/numeric-string), returning fallback when
// absent or unparseable.
func intMetadataValue(metadata map[string]any, key string, fallback int) int {
	if metadata == nil {
		return fallback
	}
	value, ok := metadata[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		return typed
	case float64:
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(typed)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

// sameTenant is the one tenant comparison this package uses, so a summary and a drill-down cannot disagree.
func sameTenant(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// recordedAfter reports whether a is strictly later than b, as instants. Equal instants answer false, which
// keeps the tie-break above: the one recorded later in the slice wins.
func recordedAfter(a, b string) bool {
	at, aerr := time.Parse(time.RFC3339, strings.TrimSpace(a))
	bt, berr := time.Parse(time.RFC3339, strings.TrimSpace(b))
	if aerr != nil || berr != nil {
		return a > b
	}
	return at.After(bt)
}
