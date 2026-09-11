package main

import (
	"sort"
	"sync"
	"time"
)

// What a node saw, kept apart from what an administrator decided.
//
// A node can observe that a device has gone quiet, or is failing attestation, or is behaving in some way worth
// a second look. None of that is grounds for cutting the device off: an observation is a reason to tell
// somebody, and blocking a device is a decision about a person's ability to work. Those are different acts and
// they live in different places — this list, and the revocation overlay.
//
// Keeping them separate is also what makes each one readable. A revocation set that mixes administrator blocks
// with machine guesses cannot answer "who decided this?", which is the first question anyone asks when a device
// stops working, and the question that took a day to answer for a two-week-old agent_dark entry nobody had
// authored.
//
// In-memory by design. A report is a notification; losing it on restart costs a notification. A revocation is
// enforcement, and forgetting one is a security failure — which is why that one is durable and this is not.
type reportedDeviceConcernList struct {
	mu sync.Mutex
	// byIdentity keeps the LATEST report per identity rather than a log. A node that keeps noticing the same
	// thing every poll would otherwise bury every other device under one repeated observation.
	byIdentity map[string]reportedDeviceConcern
}

type reportedDeviceConcern struct {
	Identity   string `json:"identity"`
	Reason     string `json:"reason"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
	Reports    int    `json:"reports"`
	Enforced   bool   `json:"enforced"` // always false; present so a reader never has to infer it
	ActionHint string `json:"action_hint"`
}

var reportedDeviceConcerns = &reportedDeviceConcernList{byIdentity: map[string]reportedDeviceConcern{}}

func (l *reportedDeviceConcernList) record(identity, reason string, now time.Time) {
	if l == nil || identity == "" {
		return
	}
	stamp := now.UTC().Format(time.RFC3339)
	l.mu.Lock()
	defer l.mu.Unlock()
	existing, ok := l.byIdentity[identity]
	if !ok {
		existing = reportedDeviceConcern{Identity: identity, FirstSeen: stamp}
	}
	existing.Reason = reason
	existing.LastSeen = stamp
	existing.Reports++
	existing.Enforced = false
	existing.ActionHint = "No enforcement was applied. To block this device, an administrator must do so explicitly."
	l.byIdentity[identity] = existing
}

// snapshot returns the reports newest-first, so the list reads as "what came in recently" rather than as a set
// that has to be sorted by whoever displays it.
func (l *reportedDeviceConcernList) snapshot() []reportedDeviceConcern {
	if l == nil {
		return []reportedDeviceConcern{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]reportedDeviceConcern, 0, len(l.byIdentity))
	for _, c := range l.byIdentity {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].Identity < out[j].Identity
	})
	return out
}

// clear drops a report once an administrator has dealt with it — by blocking the device, or by deciding the
// observation was not worth acting on. Both are decisions; neither is this list's to make.
func (l *reportedDeviceConcernList) clear(identity string) bool {
	if l == nil || identity == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.byIdentity[identity]
	delete(l.byIdentity, identity)
	return ok
}
