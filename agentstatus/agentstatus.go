// Package agentstatus is the shared, read-only status contract between the DsseSteer service (session 0, the
// authority) and the dsse-tray UI (user session, a mirror). The service holds a Status snapshot and serves it
// over an ACL'd local pipe; the tray renders it. This package is pure, platform-neutral Go so both sides agree
// on the schema + the icon/label mapping and it is unit-tested on any OS (the Windows pipe transport is
// separate).
//
// It carries NO capability to change enforcement: the tray is a mirror, not a switch.
package agentstatus

import (
	"encoding/json"
	"sync"
)

// Protection is the box's current protection posture — the same vocabulary the tray icon and the Admin Console
// device view use, so operator and user see one language.
type Protection string

const (
	// Stopped: the service is not running / not armed.
	Stopped Protection = "stopped"
	// Steering: armed, Edge reachable, traffic protected via the tunnel (the normal green state).
	Steering Protection = "steering"
	// CaptiveOnboarding: temporarily disarmed to the native network for a captive-portal sign-in window.
	CaptiveOnboarding Protection = "captive_onboarding"
	// Disarmed: fail-open disarmed to the native network (Edge outage under an acknowledged fail-open posture).
	Disarmed Protection = "disarmed"
	// Dark: fail-closed and the Edge is unreachable — traffic is blocked (secure but no connectivity).
	Dark Protection = "dark"
	// Error: an unexpected fault.
	Error Protection = "error"
)

// Icon is the tray icon color for this protection state (green=protected, amber=temporarily on native network,
// red=blocked/fault, gray=stopped). Kept here so the service and tray never disagree.
func (p Protection) Icon() string {
	switch p {
	case Steering:
		return "green"
	case CaptiveOnboarding, Disarmed:
		return "amber"
	case Dark, Error:
		return "red"
	default:
		return "gray"
	}
}

// Label is a short human label for the state (ja/en handled by the UI; this is the stable key/en fallback).
func (p Protection) Label() string {
	switch p {
	case Steering:
		return "Protected (steering)"
	case CaptiveOnboarding:
		return "Captive sign-in"
	case Disarmed:
		return "Native network (fail-open)"
	case Dark:
		return "Blocked (fail-closed, Edge unreachable)"
	case Error:
		return "Error"
	default:
		return "Stopped"
	}
}

// Status is the read-only snapshot the service publishes and the tray renders.
type Status struct {
	Protection    Protection `json:"protection"`
	Tenant        string     `json:"tenant,omitempty"`
	Group         string     `json:"group,omitempty"`
	Region        string     `json:"region,omitempty"` // current Edge endpoint / region id
	EdgeReachable bool       `json:"edge_reachable"`
	Posture       string     `json:"posture,omitempty"`        // fail-closed | fail-open
	Enrolled      bool       `json:"enrolled"`                 // has a device identity yet
	PolicyVersion int        `json:"policy_version,omitempty"` // last applied signed policy version
	AgentVersion  string     `json:"agent_version,omitempty"`
	UpdatedUnix   int64      `json:"updated_unix"` // last update (caller-supplied clock; no Date.now in this pkg)
}

// Holder is a concurrency-safe snapshot the service updates and the pipe server reads.
type Holder struct {
	mu sync.RWMutex
	s  Status
}

// NewHolder starts from an initial status (typically {Protection: Stopped}).
func NewHolder(initial Status) *Holder { return &Holder{s: initial} }

// Set applies a mutation to the snapshot under the lock.
func (h *Holder) Set(mutate func(*Status)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	mutate(&h.s)
}

// SetProtection is the common update: change the protection state and stamp the update time (caller supplies
// the clock so this package stays deterministic/testable).
func (h *Holder) SetProtection(p Protection, nowUnix int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.s.Protection = p
	h.s.UpdatedUnix = nowUnix
}

// Snapshot returns a copy of the current status (safe to hand to the pipe server / serialize).
func (h *Holder) Snapshot() Status {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.s
}

// JSON serializes the current snapshot.
func (h *Holder) JSON() ([]byte, error) {
	return json.Marshal(h.Snapshot())
}

// Parse deserializes a status snapshot (tray side).
func Parse(b []byte) (Status, error) {
	var s Status
	err := json.Unmarshal(b, &s)
	return s, err
}
