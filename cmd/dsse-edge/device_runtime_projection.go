package main

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/model"
)

// device_runtime_projection.go — the fleet's device picture, folded at arrival instead of replayed per request.
//
// ★★ WHY (2026-08-14). mergeFleetDeviceRuntime answered every Console load by querying 48 hours of shipped
// device_state changes — 2000 rows, newest first — and keeping the newest row per device. That was affordable
// while a steadily-steering device emitted ONE event, at the moment it started. It stopped being affordable
// the same day: the change signature gained a coarse clock so a device that keeps steering re-ships once a
// minute, which is what lets a remote reader say "now" instead of "at some point". Measured immediately after:
// the query took 10.7 SECONDS, and the Edge's own startup hydration — which runs the same query against a
// 20-second budget — timed out on its first two attempts three separate times in one afternoon.
//
// ★ AND THE TRUNCATION IS THE WORSE HALF. 1440 rows per day per steering device against a 2000-row cap means
// the window is not 48 hours, it is however long the noisiest devices take to fill 2000 rows: about 17 hours
// with two devices, under two hours with twenty. Newest-first truncation drops the OLDEST rows, and the oldest
// rows belong to the QUIET devices — so the busiest endpoints would silently push the idle ones off the fleet
// view entirely. The merge exists to stop devices vanishing when they move between Edges; scaling it by
// steering volume would make it vanish them by being boring instead.
//
// The shape is not new here. recordShippedAgentUpdate in audit_ingest_receiver.go was moved to arrival for
// exactly this reason, with a measurement attached: reading the fleet's update picture out of the hot store on
// every Console load took ClickHouse from idle to 340% CPU, timed out its own INGEST, and then the control
// plane would not start because its health check timed out — asking what the fleet had installed took down the
// store the answer comes from. This is the same question one table over, so it gets the same answer: fold on
// arrival, O(1) per event, and let the read be an in-memory lookup.
//
// WHAT THIS IS NOT. It is not a second source of truth. The shipped device_state log remains canonical and is
// what this is REBUILT from at startup (once, not per request). If this projection is empty because the
// process just started, the fleet view answers from the local live map alone — the same answer that node would
// have given before any of this existed — and says so rather than pretending the fleet is small.

// fleetDeviceRecord is the projection of one device's last shipped state: exactly the fields the fleet view
// renders, and nothing else. Keeping it narrow is deliberate — a projection that grows toward the full record
// becomes a second copy of the log with different bugs.
type fleetDeviceRecord struct {
	TenantID      string
	DeviceID      string
	OS            string
	LoggedInUsers []string
	Edge          string
	LastSteered   string
	Timestamp     string
	// SourceIP is the address the device reached its Edge from, carried for the same reason Posture is: the
	// node answering a fleet-wide question is usually not the node the device is connected to.
	SourceIP string
	// Posture is what the device reported about itself, carried so a node that is not the one it reports to can
	// still answer for it.
	//
	// ★ IT WAS MISSING AND THE SCREEN WENT BLANK (2026-08-14, from the operator: "posture is no longer visible
	// in the device list"). Posture is ingested by the EDGE a device reports to; the control plane has none of
	// its own. Once the Console was changed to read the fleet-wide answer first, it began rendering a view whose
	// posture column was structurally empty — not stale, not unknown, absent — while the Edge one desk away
	// held it. A projection that carries some of a record is a projection that decides, silently, which
	// questions the fleet view can be asked.
	Posture model.DevicePostureSignals
}

// fleetDeviceProjection holds the newest shipped state per (tenant, device).
//
// Bounded by the fleet, not by traffic: one entry per device however often it reports. That is the property
// that makes the refresh heartbeat affordable, and the reason the log could not be read this way directly.
// populated-by: side_effect — the audit-ingest receiver folds every device_state record an Edge SHIPS. The
// path is named because the question it invites has a live answer: an Edge whose shipping is broken never
// appears here at all. region-b spent 2026-08-14 in exactly that state — it held 176 records because it had
// been configured with the ingest URL and token but not the client certificate the receiver requires — and its
// devices were absent from the fleet view, not stale in it. That is acceptable only because it is now audible:
// the shipper logs the first failure, a slow heartbeat while it persists, and recovery.
//
// restart-durability: cp_durable — the shipped device_state log is the record; this is rebuilt from it by
// seedFleetDeviceProjection at startup and fed by the audit-ingest receiver thereafter. Losing it costs the
// fleet view nothing an operator can see beyond the seconds before the seed completes, and during those
// seconds the view says fleet_wide=false rather than presenting one node as the fleet.
type fleetDeviceProjection struct {
	mu      sync.RWMutex
	byName  map[string]map[string]fleetDeviceRecord // tenant -> device -> newest
	seeded  bool
	seededN int
}

func newFleetDeviceProjection() *fleetDeviceProjection {
	return &fleetDeviceProjection{byName: map[string]map[string]fleetDeviceRecord{}}
}

// Fold records a shipped device_state row, keeping the newest per device.
//
// Newest by the row's own timestamp, not by arrival order: the shipper RETAINS and REPLAYS on failure, so a
// batch that was stuck for an afternoon arrives after the rows that overtook it. region-b did exactly that on
// 2026-08-14 — 176 records delivered at once, oldest first — and an arrival-ordered fold would have left every
// device described by whichever row happened to land last.
func (p *fleetDeviceProjection) Fold(row map[string]any) {
	if p == nil || row == nil {
		return
	}
	rec := fleetDeviceRecord{
		TenantID:      strings.TrimSpace(stringFromRow(row, "tenant_id")),
		DeviceID:      strings.TrimSpace(stringFromRow(row, "device_id")),
		OS:            strings.TrimSpace(stringFromRow(row, "os")),
		LoggedInUsers: stringsFromRow(row, "logged_in_users"),
		Edge:          strings.TrimSpace(stringFromRow(row, "edge")),
		SourceIP:      strings.TrimSpace(stringFromRow(row, "source_ip")),
		LastSteered:   strings.TrimSpace(stringFromRow(row, "last_steered")),
		Timestamp:     strings.TrimSpace(stringFromRow(row, "timestamp")),
		Posture: model.DevicePostureSignals{
			DiskEncryptionEnabled:   boolPtrFromRow(row, "disk_encryption_enabled"),
			FirewallEnabled:         boolPtrFromRow(row, "firewall_enabled"),
			EnforcementAgentHealthy: boolPtrFromRow(row, "enforcement_agent_healthy"),
			CollectedAt:             strings.TrimSpace(stringFromRow(row, "posture_collected_at")),
			Source:                  strings.TrimSpace(stringFromRow(row, "posture_source")),
		},
	}
	if rec.DeviceID == "" || rec.Timestamp == "" {
		// A row with no device or no time is not a state of anything. Same rule as seedFromHistory.
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	devices := p.byName[rec.TenantID]
	if devices == nil {
		devices = map[string]fleetDeviceRecord{}
		p.byName[rec.TenantID] = devices
	}
	if existing, ok := devices[rec.DeviceID]; ok && existing.Timestamp >= rec.Timestamp {
		return
	}
	devices[rec.DeviceID] = rec
}

// Devices returns the projection for one tenant, and whether this projection has ever been seeded.
//
// The second return value is the difference between "this fleet has no other devices" and "this process has
// not read the history yet", which are the same empty map and must not read the same to a caller.
func (p *fleetDeviceProjection) Devices(tenantID string) ([]fleetDeviceRecord, bool) {
	if p == nil {
		return nil, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]fleetDeviceRecord, 0, len(p.byName[strings.TrimSpace(tenantID)]))
	for _, rec := range p.byName[strings.TrimSpace(tenantID)] {
		out = append(out, rec)
	}
	return out, p.seeded
}

// Seed folds a batch of history rows and marks the projection as populated. Called ONCE at startup, from the
// same query the per-request path used to run.
func (p *fleetDeviceProjection) Seed(rows []map[string]any) int {
	if p == nil {
		return 0
	}
	for _, row := range rows {
		p.Fold(row)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seeded = true
	n := 0
	for _, devices := range p.byName {
		n += len(devices)
	}
	p.seededN = n
	return n
}

// fleetDeviceProjectionStore is the process-wide projection, fed by the audit-ingest receiver.
var fleetDeviceProjectionStore = newFleetDeviceProjection()

// mergeFleetDeviceRuntimeFromProjection fills a node's live view with devices it has not seen itself.
//
// The local map still wins where they overlap, for the reason it always did: this node's view is being written
// by traffic as the request is served, while the projection records what some Edge last reported.
func mergeFleetDeviceRuntimeFromProjection(local map[string]deviceRuntimeView, p *fleetDeviceProjection,
	tenantID string, now time.Time) (map[string]deviceRuntimeView, bool) {
	records, seeded := p.Devices(tenantID)
	out := make(map[string]deviceRuntimeView, len(local)+len(records))
	for id, v := range local {
		out[id] = v
	}
	for _, rec := range records {
		if _, seenHere := local[rec.DeviceID]; seenHere {
			continue // live beats recorded
		}
		view := deviceRuntimeView{
			OS:            rec.OS,
			LoggedInUsers: rec.LoggedInUsers,
			LastSeen:      rec.Timestamp,
			Edge:          rec.Edge,
			LastSteered:   rec.LastSteered,
			SourceIP:      rec.SourceIP,
			Posture:       rec.Posture,
		}
		// steer_active is derived HERE rather than trusted from the record, because the record is a moment and
		// this answers a question about now. A device that was steering an hour ago is not steering.
		if view.LastSteered != "" {
			if at, perr := time.Parse(time.RFC3339, view.LastSteered); perr == nil {
				view.SteerActive = now.Sub(at) < steerActiveWindow
			}
		}
		out[rec.DeviceID] = view
	}
	return out, seeded
}

// seedFleetDeviceProjection builds the projection from the canonical history, once.
//
// Bounded the same way the per-request query was — a 48-hour window and a row cap — because this is the same
// read, moved. What changed is how often it runs: once per process instead of once per Console load, which is
// the difference between a 10-second query nobody notices and a 10-second query on every page.
func seedFleetDeviceProjection(p *fleetDeviceProjection, store hotstore.Store, tenantID string) {
	if p == nil || store == nil {
		// Nothing to seed from. Leaving `seeded` false is the point: the fleet view then says it is answering
		// for one node rather than presenting one node's devices as the fleet.
		log.Printf("device-runtime: no history store on this node — the fleet projection stays unseeded and the " +
			"fleet view will answer for this node only")
		return
	}
	started := time.Now()
	rows, err := adminLogSearchWithLimitBounds(store, tenantID, "device_state", fleetDeviceRuntimeQuery(time.Now()), 2000, 5000)
	if err != nil {
		log.Printf("★ device-runtime: could not seed the fleet projection (%v) — the fleet view will answer for "+
			"this node only until shipped events fill it in", err)
		return
	}
	n := p.Seed(rows.rows)
	log.Printf("device-runtime: fleet projection seeded from %d shipped row(s) -> %d device(s) in %s",
		len(rows.rows), n, time.Since(started).Truncate(time.Millisecond))
}

// boolPtrFromRow reads a tri-state from a shipped row: true, false, or ABSENT.
//
// A pointer rather than a bool because the three states are three different answers — "this device reports its
// disk is not encrypted" and "this device has not told us" must not render the same, which is the whole reason
// DevicePostureSignals is built from pointers. JSON gives back float64/bool/nil depending on the encoder, so
// the shapes that can carry a boolean are all accepted and anything else reads as absent.
func boolPtrFromRow(row map[string]any, key string) *bool {
	switch v := row[key].(type) {
	case bool:
		b := v
		return &b
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true":
			b := true
			return &b
		case "false":
			b := false
			return &b
		}
	}
	return nil
}
