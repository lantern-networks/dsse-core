package main

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// device_posture_ingest.go — the per-device RUNTIME store the endpoint agent feeds over the steer transport, so
// the Devices list can show, per device: the OS, who is logged in, whether it is actively steering, and its
// posture (disk encryption + firewall). Two feeds, both keyed by the verified (T) transport device identity:
//   - steer-mux CONNECT (per connection ≈ per device): OS + posture headers + a last-seen stamp.
//   - steer OPEN frame (per flow): the logged-in OS user that originated the flow (a device is shared).
// All of it is an agent CLAIM (dashboard signal + trust floor, not proof). EDR is out for now (see the
// signal-contract design).
//
// CONNECT headers:
//   X-Dsse-Device-OS:          e.g. "macOS 15.5"
//   X-Dsse-Posture-Encryption: on|off       (disk encryption / FileVault / BitLocker)
//   X-Dsse-Posture-Firewall:   on|off       (OS application firewall)
//   X-Dsse-Posture-Source:     macos_collector|windows_collector|...

const (
	postureHeaderEncryption = "X-Dsse-Posture-Encryption"
	postureHeaderFirewall   = "X-Dsse-Posture-Firewall"
	postureHeaderSource     = "X-Dsse-Posture-Source"
	deviceHeaderOS          = "X-Dsse-Device-OS"

	// steerActiveWindow: a device seen on the steer transport within this window is reported as actively steering.
	steerActiveWindow = 2 * time.Minute

	// steerRefreshInterval: how often a device that KEEPS steering re-ships its state, so a control plane
	// merging change events can answer in the present tense. See device_runtime_steering_lapse.go for why this
	// exists and what it costs (one event per minute per actively steering device — not per flow).
	steerRefreshInterval = time.Minute
)

type deviceRuntimeInfo struct {
	os            string
	loggedInUsers map[string]bool
	lastSeen      time.Time
	// lastSteered is the last time this device actually STEERED something: a mux CONNECT or a flow OPEN.
	//
	// ★★ IT IS NOT lastSeen, AND CONFLATING THEM TOLD AN OPERATOR THE OPPOSITE OF THE TRUTH (2026-08-13, from
	// the lab). steer_active was `now - lastSeen < window`, and lastSeen is stamped by ANY contact — including
	// the update courier fetching a manifest over the (T) transport. So a Mac whose only conversation with the
	// Edge in twenty-five minutes was "what version should I run" was reported as actively steering, with no
	// traffic passing through the Edge at all. The screen said protected; the evidence said "it asked us a
	// question".
	//
	// A device that is idle and a device that is not steering look the same from here, and they should: this
	// says what we HAVE evidence of, and the view says which one it is rather than asserting the stronger claim.
	lastSteered time.Time
	// steering is the last STATE that was reported, so a device starting or stopping steering produces one
	// event and a device that goes on steering produces none. Without it the fleet-wide view learns about a
	// failover only when something else about the device happens to change.
	steering bool
	// edge names the node this state came from. Empty means "this node": only rows hydrated from another
	// Edge's shipped history carry it, and that is exactly the case an operator needs told — a device steering
	// somewhere else looks, from here, like a device that is not steering at all.
	edge    string
	posture model.DevicePostureSignals
	tenant  string
	// sourceIP is the address this device reached the Edge FROM. It is taken from the connection and never
	// from anything the device says about itself: a device that could name its own address could name any.
	//
	// ★★★ IT IS THE ADDRESS AN L4 FRONT DOOR WOULD OTHERWISE HAVE ERASED. Every device in a region arrives
	// through one address (invariant 9), so without the PROXY header the connection reports the front door
	// and every device in the fleet appears to be at the same place. What is recorded here is only as true as
	// -trusted-front-doors is correct, which is why that flag names addresses rather than accepting a header
	// from anyone.
	sourceIP string
	// lastSig is a signature of the last STATE we emitted a change event for (OS + users + posture). Only a change
	// to it emits a new event — so Postgres records device-state CHANGES, not every heartbeat (steer_active is
	// time-derived, not part of the signature — it does not spam changes).
	lastSig string
}

// deviceStateChangeEmit, when set at startup, is called on a device STATE change to persist a change event
// (routed to the "device_state" hot-store stream -> Postgres). nil = no persistence (change events are dropped).
var deviceStateChangeEmit func(event map[string]any)

// endpointRuntimeStore keeps the latest runtime facts per device, keyed by the verified (T) transport device
// identity.
//
// restart-durability: cp_durable — the control plane holds the durable device-state history (the Edge emits a
// change event, ships it, the CP persists it) and this map is rehydrated from there at startup. See
// device_runtime_hydrate.go. Before that read-back existed, a restart emptied the operator's fleet view and a
// device returned only if it happened to dial a new mux.
//
// populated-by: side_effect — the steer-mux CONNECT (ingestFromConnect) and the flow OPEN (recordSteeredFlow).
// Naming the path names the gap: POST /devices/{id}/heartbeat does NOT write here, so between restarts a device
// is present in this store because it STEERED, not because it is alive. A device that is up and heartbeating but
// sending no steered traffic is absent from it. The startup hydration covers the restart case; it does not make
// this an assertion. Moving it to one means feeding the heartbeat handler in here, which is a change to what the
// fleet view MEANS (reachable vs steering) and should be decided, not slid in.
type endpointRuntimeStore struct {
	mu sync.RWMutex
	m  map[string]*deviceRuntimeInfo
}

func newEndpointRuntimeStore() *endpointRuntimeStore {
	return &endpointRuntimeStore{m: map[string]*deviceRuntimeInfo{}}
}

// deviceRuntime is the process-wide store, fed by the steer-mux CONNECT + OPEN handlers and read by
// GET /admin/device-runtime. In-memory (lab floor; a durable store is the production form).
var deviceRuntime = newEndpointRuntimeStore()

func (s *endpointRuntimeStore) entry(deviceID string) *deviceRuntimeInfo {
	e := s.m[deviceID]
	if e == nil {
		e = &deviceRuntimeInfo{loggedInUsers: map[string]bool{}}
		s.m[deviceID] = e
	}
	return e
}

// ingestFromConnect reads the OS + posture headers off a steer-mux CONNECT and records them for deviceID, and
// stamps last-seen. Returns the parsed posture (and whether posture was present) so the caller can log it.
func (s *endpointRuntimeStore) ingestFromConnect(deviceID, tenantID string, h http.Header, sourceIP string, now time.Time) (model.DevicePostureSignals, bool) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return model.DevicePostureSignals{}, false
	}
	enc, encOK := parsePostureBool(h.Get(postureHeaderEncryption))
	fw, fwOK := parsePostureBool(h.Get(postureHeaderFirewall))
	os := sanitizeRuntimeField(h.Get(deviceHeaderOS), 64)

	s.mu.Lock()
	e := s.entry(deviceID)
	e.lastSeen = now
	if sourceIP != "" {
		e.sourceIP = sourceIP
	}
	// A steer-mux CONNECT is the device opening its traffic channel, so it counts as steering — unlike the
	// update courier, which speaks to the same Edge over the same transport and steers nothing.
	e.lastSteered = now
	e.steering = true
	if tenantID != "" {
		e.tenant = tenantID
	}
	if os != "" {
		e.os = os
	}
	var ret model.DevicePostureSignals
	present := false
	if encOK || fwOK {
		p := model.DevicePostureSignals{CollectedAt: now.UTC().Format(time.RFC3339), Source: sanitizeRuntimeField(h.Get(postureHeaderSource), 64)}
		if encOK {
			p.DiskEncryptionEnabled = &enc
		}
		if fwOK {
			p.FirewallEnabled = &fw
		}
		e.posture = p
		ret, present = p, true
	}
	event := s.changeEventLocked(e, deviceID)
	s.mu.Unlock()
	emitDeviceStateChange(event) // persist only a CHANGE, off the lock
	return ret, present
}

// ingestFromReport records presence and posture from the agent's periodic report, rather than from the
// steer-mux CONNECT.
//
// ★ WHY A SECOND INGEST PATH RATHER THAN A SECOND CALLER OF THE FIRST. The CONNECT path reads HTTP headers off
// a tunnel handshake; this one takes decoded values off a JSON body that arrives every 15 seconds whether or
// not the device is carrying any traffic. Same store, same change-event semantics, different evidence.
//
// The gap it closes is the one this file's own doc comment names: "a device is present in this store because
// it STEERED, not because it is alive". Measured on the reference Edge, 2026-08-10 — mac-dev-1, enrolled and
// reporting every 15 s, had NO entry at all while win-dev-1 had a full one, so the Console said the macOS NE
// reported neither disk encryption nor firewall. Nothing was wrong with the collector; the only channel that
// carried the answer was one that device was not using.
//
// Pointers rather than bools, deliberately: absent means the agent did not say. An unreported signal and a
// disabled one need opposite responses, and collapsing them turns "we cannot see this machine" into "this
// machine is non-compliant".
func (s *endpointRuntimeStore) ingestFromReport(deviceID, tenantID, osName string, enc, fw *bool, source, sourceIP string, now time.Time) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return
	}
	s.mu.Lock()
	e := s.entry(deviceID)
	e.lastSeen = now
	if sourceIP != "" {
		e.sourceIP = sourceIP
	}
	if tenantID != "" {
		e.tenant = tenantID
	}
	if o := sanitizeRuntimeField(osName, 64); o != "" {
		e.os = o
	}
	if enc != nil || fw != nil {
		p := model.DevicePostureSignals{
			CollectedAt: now.UTC().Format(time.RFC3339),
			Source:      sanitizeRuntimeField(source, 64),
		}
		// Carried forward individually: an agent that can read one signal and not the other must not erase the
		// one it previously reported by reporting the other.
		if enc != nil {
			v := *enc
			p.DiskEncryptionEnabled = &v
		} else {
			p.DiskEncryptionEnabled = e.posture.DiskEncryptionEnabled
		}
		if fw != nil {
			v := *fw
			p.FirewallEnabled = &v
		} else {
			p.FirewallEnabled = e.posture.FirewallEnabled
		}
		e.posture = p
	}
	event := s.changeEventLocked(e, deviceID)
	s.mu.Unlock()
	emitDeviceStateChange(event)
}

// changeSignature is the state whose CHANGE is worth persisting: OS + logged-in users + posture. Extracted so
// the startup hydration can seed it from restored state — a device restored from history and then reporting the
// SAME state must not look like a transition and emit a spurious change event.
func (e *deviceRuntimeInfo) changeSignature() string {
	users := make([]string, 0, len(e.loggedInUsers))
	for u := range e.loggedInUsers {
		users = append(users, u)
	}
	sort.Strings(users)
	// ★ THE STEERING COMPONENT CARRIES A COARSE CLOCK (2026-08-14). It used to be the bare boolean, so a device
	// that kept steering never differed from itself and shipped nothing after its first flow — freezing
	// last_steered on every OTHER Edge's copy of it, two minutes after which the fleet view called the whole
	// fleet idle. Bucketing to steerRefreshInterval re-ships at most once a minute while steering, and not at
	// all when it stops (the sweeper handles that edge). The bucket is derived from lastSteered, so the startup
	// hydration seeds an identical signature from the same field and still does not emit false history.
	steer := "off"
	if e.steering {
		steer = "on@" + strconv.FormatInt(e.lastSteered.UTC().Truncate(steerRefreshInterval).Unix(), 10)
	}
	// The address is part of the state: a device that moves to another network is the same device somewhere
	// else, and that is a change an operator is entitled to see. It changes when the network changes and not
	// on a clock, so including it re-ships nothing on its own.
	return e.os + "\x1f" + strings.Join(users, ",") + "\x1f" + steer + "\x1f" + boolPtrLog(e.posture.DiskEncryptionEnabled) + "\x1f" + boolPtrLog(e.posture.FirewallEnabled) + "\x1f" + e.sourceIP
}

// changeEventLocked (mutex held) returns a device-state change event to persist when e's meaningful state
// (OS + logged-in users + posture) differs from the last emitted signature, else nil. steer_active is
// time-derived and deliberately excluded so it does not spam changes.
func (s *endpointRuntimeStore) changeEventLocked(e *deviceRuntimeInfo, deviceID string) map[string]any {
	users := make([]string, 0, len(e.loggedInUsers))
	for u := range e.loggedInUsers {
		users = append(users, u)
	}
	sort.Strings(users)
	if e.os == "" && len(users) == 0 && e.posture.DiskEncryptionEnabled == nil && e.posture.FirewallEnabled == nil {
		return nil // nothing meaningful yet
	}
	// A steering transition is a change worth shipping; steering CONTINUING is not, or every device would emit
	// an event per flow. changeSignature carries the boolean, not the timestamp, which is the difference between
	// one event per failover and one per minute per device.
	sig := e.changeSignature()
	if sig == e.lastSig {
		return nil
	}
	e.lastSig = sig
	return map[string]any{
		"tenant_id": e.tenant,
		"device_id": deviceID,
		"event":     "device_state_changed",
		"os":        e.os,
		// Where it reached us from, so a fleet-wide view can answer it for a device steering through another
		// node. A reader that does not know this field is the failure this repository has hit twice; both
		// restore paths below read it.
		"source_ip":               e.sourceIP,
		"logged_in_users":         users,
		"disk_encryption_enabled": e.posture.DiskEncryptionEnabled,
		"firewall_enabled":        e.posture.FirewallEnabled,
		// ★ AND WHEN, AND FROM WHAT (2026-08-14). The two booleans shipped and the rest did not, so a reader on
		// another node could say a device was encrypted but not whether that was measured a minute ago or last
		// week — and "collected_at" is the difference between a posture answer and a posture memory. The
		// enforcement-agent signal travels for the same reason: it is the tamper-evident one, and it was the
		// field most worth having off-box.
		"enforcement_agent_healthy": e.posture.EnforcementAgentHealthy,
		"posture_collected_at":      e.posture.CollectedAt,
		"posture_source":            e.posture.Source,
		// ★ WHERE, AND WHETHER IT IS STEERING (2026-08-14). A fleet spans Edges, and a device that fails over to
		// another one vanishes from the Edge the Console happens to read — which is how a Mac that was steering
		// perfectly through region-b was reported as not steering at all. These two fields are what let the
		// control plane answer for the whole fleet instead of for one node.
		"edge": deviceRuntimeEdgeID,
		// The region on its own, beside the "<region>/<cluster>" identity above. A reader that wants the
		// region should not have to know how another field is punctuated.
		"edge_region_id": edgeRuntimeRegionID,
		"last_steered":   rfc3339OrEmpty(e.lastSteered),
		"timestamp":      e.lastSeen.UTC().Format(time.RFC3339),
	}
}

func emitDeviceStateChange(event map[string]any) {
	if event != nil && deviceStateChangeEmit != nil {
		deviceStateChangeEmit(event)
	}
}

// recordSteeredFlow records that this device carried a flow — the only evidence of steering there is — and,
// when the agent sent one, the logged-in OS user that originated it. A device is shared, so the users
// accumulate.
//
// The user is OPTIONAL and always was — the per-flow metadata section is an extension, and an older agent
// sends "host:port" alone. Callers must not gate the call on having one. This was named recordFlowUser until
// 2026-08-14, and under that name its one caller invoked it only when a username was present, so any flow
// without one left the device recorded as never having steered.
func (s *endpointRuntimeStore) recordSteeredFlow(deviceID, tenantID, osUser string, now time.Time) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return
	}
	s.mu.Lock()
	e := s.entry(deviceID)
	e.lastSeen = now
	// A flow OPEN is steering: this is traffic being carried, not a device asking a question.
	e.lastSteered = now
	e.steering = true
	if tenantID != "" {
		e.tenant = tenantID
	}
	if u := sanitizeRuntimeField(osUser, 128); u != "" {
		e.loggedInUsers[u] = true
	}
	event := s.changeEventLocked(e, deviceID)
	s.mu.Unlock()
	emitDeviceStateChange(event)
}

// rfc3339OrEmpty renders an instant, or "" when there is nothing to render — because "never" and "the zero
// time" must not print as 0001-01-01, which reads as a date somebody could act on.
func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// deviceRuntimeView is the JSON shape GET /admin/device-runtime returns per device.
type deviceRuntimeView struct {
	OS            string   `json:"os"`
	LoggedInUsers []string `json:"logged_in_users"`
	LastSeen      string   `json:"last_seen"`
	SteerActive   bool     `json:"steer_active"`
	// LastSteered is when this device last actually steered traffic. Empty means this Edge has never seen it
	// steer, which is a different statement from "not steering now" and both are different from "offline".
	LastSteered string `json:"last_steered,omitempty"`
	// Edge is which node this device is steering through. Empty means the node answering the request. It is the
	// field that was missing when a Mac failing over to region-b read as "not steering" on region-a.
	Edge string `json:"edge,omitempty"`
	// SourceIP is the address this device reached the Edge from. Empty means this node has not seen it
	// connect — a device restored from another node's shipped history before it has spoken here.
	SourceIP string                     `json:"source_ip,omitempty"`
	Posture  model.DevicePostureSignals `json:"posture"`
}

// deviceRuntimeEdgeID names the node whose view this is, so a fleet-wide answer can say WHERE a device is
// steering. Set once at startup from -edge-region-id/-edge-cluster-id.
var deviceRuntimeEdgeID = ""

// edgeRuntimeRegionID is this node's REGION on its own, which is what a record has to carry for the region to
// be answerable of the record.
//
// ★★★ THE SAME FACT WAS SPELLED TWO WAYS, AND ONE OF THEM WAS NOT THE REGION (2026-08-24, measured on the
// lab's 3,085,761 rows). Access and audit records carry edge_region_id; device_state carried "edge" as
// "<region>/<cluster>" and config_generations carried nothing at all. In the hot store, whose schema has no
// region column, that meant 29,859 rows from which no region could be read without splitting a string that
// only one stream used — and 764 from which it could not be read at all.
//
// Deciding where a region's logs may live, or be retained, or be deleted, starts with every record being able
// to say which region it is from.
var edgeRuntimeRegionID = ""

func (s *endpointRuntimeStore) snapshot(now time.Time) map[string]deviceRuntimeView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]deviceRuntimeView, len(s.m))
	for id, e := range s.m {
		users := make([]string, 0, len(e.loggedInUsers))
		for u := range e.loggedInUsers {
			users = append(users, u)
		}
		sort.Strings(users)
		last := ""
		if !e.lastSeen.IsZero() {
			last = e.lastSeen.UTC().Format(time.RFC3339)
		}
		out[id] = deviceRuntimeView{
			OS:            e.os,
			LoggedInUsers: users,
			LastSeen:      last,
			SteerActive:   !e.lastSteered.IsZero() && now.Sub(e.lastSteered) < steerActiveWindow,
			LastSteered:   rfc3339OrEmpty(e.lastSteered),
			Edge:          e.edge,
			SourceIP:      e.sourceIP,
			Posture:       e.posture,
		}
	}
	return out
}

func boolPtrLog(b *bool) string {
	if b == nil {
		return "unknown"
	}
	if *b {
		return "on"
	}
	return "off"
}

// parsePostureBool maps on/true/1/enabled -> true, off/false/0/disabled -> false. Returns ok=false for anything
// else (including empty) so an unreported signal stays unknown rather than defaulting to a (wrong) value.
func parsePostureBool(v string) (val bool, ok bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "1", "enabled", "yes":
		return true, true
	case "off", "false", "0", "disabled", "no":
		return false, true
	default:
		return false, false
	}
}

func sanitizeRuntimeField(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
