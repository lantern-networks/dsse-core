package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/revocation"
)

// CP→Edge SHARED REVOCATION overlay (Phase 3 — edge_horizontal_scale_and_failover_design.md §Phase 3). Unlike
// config (eventually-consistent, ~10s pull), revocation must be FLEET-CONSISTENT at LOW latency: a device
// revoked on the control plane must be refused on EVERY node within seconds, so it cannot reconnect to a
// different node to evade a kill-switch. This is a dedicated FAST poller (default ~2s) of a small overlay,
// separate from the config bundle. Fail-safe direction is fail-CLOSED: a fetch error KEEPS the last synced
// revocations (a CP blip never un-revokes). The CP set is persisted, so it survives a CP restart.

type revocationSource struct {
	url string // control-plane admin base (reuses -config-source-url; single-CP fallback)
	// endpoints, when set (multi-region CP), provides the CURRENT healthy CP base URL (region failover); "" =
	// no in-boundary CP reachable → keep the last revocation set. See cp_endpoint_failover.go.
	endpoints *cpEndpointSelector
	token     string
	interval  time.Duration
	client    *http.Client
	// status is what this loop has managed to do, so /healthz and the posture check can be asked instead of a
	// container log. nil is tolerated (tests that only exercise the apply logic).
	status *revocationSyncStatus
}

// baseURL is the CP base to talk to now: the current healthy CP when region failover is configured, else the
// fixed single-CP URL. "" = no in-boundary CP reachable.
func (s revocationSource) baseURL() string {
	if s.endpoints != nil {
		return s.endpoints.CurrentBaseURL()
	}
	return s.url
}

// revocationFeed is the wire shape served by GET /admin/revocations. epoch + generation mirror the config
// bundle: the puller re-applies on a newer generation OR a changed epoch (a CP restart resets the in-memory
// generation; the persisted revoked set is still authoritative, so re-baselining is safe and fail-closed).
type revocationFeed struct {
	Generation uint64            `json:"generation"`
	Epoch      string            `json:"epoch,omitempty"`
	Revoked    map[string]string `json:"revoked"`             // identity -> non-secret reason code
	HighRisk   map[string]string `json:"high_risk,omitempty"` // deviceID -> severity (decision-path)
	// Authoritative marks this as a COMPLETE set from the config authority, which is what makes an EMPTY one
	// meaningful. Zero revocations and "I could not tell you" are the same bytes otherwise, so a puller had to
	// assume the worse of the two and keep whatever it held — correct, but it also meant releasing the LAST
	// revocation never propagated, and the only way to let a device back in was to restart the Edge. Set only
	// by a process that IS the control plane. Absent (an older CP) reads as false, which keeps the old, safe
	// behaviour rather than trusting a field that was never sent.
	Authoritative bool `json:"authoritative,omitempty"`
}

// revocationReport is the node→CP propagation payload (slice 3b): a node ships its own auto-revocation up so
// the control plane redistributes it fleet-wide.
type revocationReport struct {
	Identity string `json:"identity"`
	Reason   string `json:"reason"`
}

// reportFunc returns a reporter (set via SetReporter on a puller) that POSTs what this node observed to the
// control plane's POST /admin/revocations/report, ASYNC + best-effort. Failure is logged and blocks nothing.
//
// It used to mean more than it does. A device this node decided had gone dark was reported, and the control
// plane revoked it fleet-wide — no administrator anywhere in the chain, and an entry that outlived the code
// that wrote it. The report is now exactly what its name says: this node saw something, somebody should look.
// The control plane records it and enforces nothing; blocking a device stays an explicit administrator act.
func (s revocationSource) reportFunc() func(identity, reason string) {
	return func(identity, reason string) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			body, _ := json.Marshal(revocationReport{Identity: identity, Reason: reason})
			base := s.baseURL()
			if strings.TrimSpace(base) == "" {
				return // no in-boundary CP reachable — the report is retried on the next auto-revocation
			}
			url := strings.TrimRight(base, "/") + "/admin/revocations/report"
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+s.token)
			req.Header.Set("content-type", "application/json")
			resp, err := s.client.Do(req)
			if err != nil {
				log.Printf("revocation report: shipping %q to the control plane failed (kept local): %v", identity, err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				log.Printf("revocation report: control plane returned %d for %q", resp.StatusCode, identity)
				return
			}
			log.Printf("revocation report: shipped node-local revocation %q to the control plane for fleet redistribution", identity)
		}()
	}
}

func (s revocationSource) fetch(ctx context.Context) (revocationFeed, error) {
	base := s.baseURL()
	if strings.TrimSpace(base) == "" {
		return revocationFeed{}, fmt.Errorf("no in-boundary control plane reachable (keeping last revocations)")
	}
	url := strings.TrimRight(base, "/") + "/admin/revocations"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return revocationFeed{}, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return revocationFeed{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return revocationFeed{}, fmt.Errorf("control plane returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var feed revocationFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return revocationFeed{}, fmt.Errorf("decode revocation feed: %w", err)
	}
	return feed, nil
}

// revocationSyncStatus is what this loop has actually managed to do, kept so something other than a container
// log can be asked.
//
// ★★ WHY THIS EXISTS (2026-08-17, found on the lab). This poller had been failing every two seconds since the
// Edge booted — 645 times in that container's life, 1893 across restarts — with
// "control plane returned 403: admin api token scope admin.endpoints.read is required". Meanwhile:
// /healthz said {"status":"ok"}, the security-posture check reported 24 passed / 0 failed, and the Console
// showed nothing. The one sync the design calls FLEET-CONSISTENT AT LOW LATENCY — the one that stops a
// revoked device reconnecting to a different node to evade a kill-switch — was the only sync with no status
// anywhere, while the slower, eventually-consistent config pull had status in /healthz, in an admin route and
// in the posture check.
//
// A revoked device was not refused by this node, and nothing in the product said so. Fail-closed protected
// the data (the last synced set is kept) and hid the outage: an overlay that never received a first set is
// indistinguishable, from the outside, from one whose control plane has nothing to revoke.
type revocationSyncStatus struct {
	mu sync.RWMutex
	// haveApplied is the load-bearing one: FALSE means this node has never held a set from the control plane,
	// so every revocation the CP knows about is unenforced here.
	haveApplied     bool
	lastAppliedAt   time.Time
	lastGeneration  uint64
	lastCount       int
	lastPollAt      time.Time
	lastError       string
	lastErrorAt     time.Time
	consecutiveFail int
}

func (s *revocationSyncStatus) recordFailure(err error, at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastPollAt = at
	s.lastError = err.Error()
	s.lastErrorAt = at
	s.consecutiveFail++
}

func (s *revocationSyncStatus) recordApplied(generation uint64, count int, at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastPollAt = at
	s.haveApplied = true
	s.lastAppliedAt = at
	s.lastGeneration = generation
	s.lastCount = count
	s.lastError = ""
	s.consecutiveFail = 0
}

// recordPoll marks a pull that succeeded but had nothing newer to apply — the steady state.
func (s *revocationSyncStatus) recordPoll(at time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastPollAt = at
	s.lastError = ""
	s.consecutiveFail = 0
}

func stampOrEmpty(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *revocationSyncStatus) snapshot() map[string]any {
	if s == nil {
		return map[string]any{"enabled": false}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]any{
		"enabled":              true,
		"have_applied":         s.haveApplied,
		"last_applied_at":      stampOrEmpty(s.lastAppliedAt),
		"last_generation":      s.lastGeneration,
		"revocation_count":     s.lastCount,
		"last_poll_at":         stampOrEmpty(s.lastPollAt),
		"last_error":           s.lastError,
		"last_error_at":        stampOrEmpty(s.lastErrorAt),
		"consecutive_failures": s.consecutiveFail,
	}
}

// run pulls immediately, then every interval, applying the CP's revocation set to the local overlay's synced
// layer when the control plane's generation is newer OR its epoch changed (a restart). A failed pull KEEPS the
// last synced set (fail-closed — never un-revoke on a CP blip).
func (s revocationSource) run(ctx context.Context, overlay *revocation.AdmissionRevocations, highRisk *revocation.HighRiskOverlay) {
	var lastApplied uint64
	var lastEpoch string
	haveApplied := false
	pull := func(initial bool) {
		feed, err := s.fetch(ctx)
		if err != nil {
			s.status.recordFailure(err, time.Now())
			if initial {
				log.Printf("revocation sync: initial pull from %s failed (keeping local revocations): %v", s.url, err)
			} else {
				log.Printf("revocation sync: pull failed (keeping revocations): %v", err)
			}
			return
		}
		apply := !haveApplied || feed.Epoch != lastEpoch || feed.Generation > lastApplied
		if !apply {
			// Nothing newer, but the control plane ANSWERED — which is the difference between "up to date" and
			// "has never heard from the authority", and the whole reason this status exists.
			s.status.recordPoll(time.Now())
			return
		}
		// A device becoming high-risk in this pull used to lose its standing east-west grants on every node.
		// That is gone. Arriving in the high-risk feed is a SIGNAL: it reaches each node's decision path, and a
		// policy gating on risk_state_severity is what refuses the device. Enforcement belongs to the rules an
		// operator wrote, where it can be read, scoped and argued with — not to a sync loop reacting to a mark.
		// An empty revocation set must never silently un-revoke the fleet — but it must be possible to let a
		// device back in. Those pulled against each other until the feed said which kind of empty it was.
		//
		// Authoritative means the control plane is telling us its complete set, so zero means zero and an
		// administrator's restore reaches every node. Without it, zero is indistinguishable from a blank
		// answer, and the safe reading is to keep what we hold. That safe reading used to be the ONLY one, so
		// releasing the last revocation propagated to nobody and the device stayed locked out until the Edge
		// was restarted — a kill-switch that could be pressed but not released by the path that pressed it.
		keptLocal := false
		if len(feed.Revoked) == 0 && overlay.SyncedCount() > 0 && !feed.Authoritative {
			keptLocal = true
			log.Printf("revocation sync: control plane sent ZERO revocations while this Edge holds %d synced revocation(s), and did NOT mark the set authoritative — KEEPING them (nothing was released). An authoritative empty set does release; this one could not be told apart from a blank answer.", overlay.SyncedCount())
		} else {
			overlay.ReplaceSynced(feed.Revoked)
		}
		if highRisk != nil {
			highRisk.ReplaceSynced(feed.HighRisk)
		}
		lastApplied = feed.Generation
		lastEpoch = feed.Epoch
		haveApplied = true
		// Report what actually happened. This line used to say "applied N revocations" even on the path that
		// had just refused to apply them, so an operator reading the log during an incident was told the
		// opposite of the truth at the one moment it mattered.
		if keptLocal {
			s.status.recordApplied(feed.Generation, overlay.SyncedCount(), time.Now())
			log.Printf("revocation sync: generation %d from the control plane — revocations NOT applied (kept %d local); %d high-risk device(s) applied", feed.Generation, overlay.SyncedCount(), len(feed.HighRisk))
		} else {
			s.status.recordApplied(feed.Generation, len(feed.Revoked), time.Now())
			log.Printf("revocation sync: applied generation %d (%d revocation(s), %d high-risk device(s)) from the control plane", feed.Generation, len(feed.Revoked), len(feed.HighRisk))
		}
	}
	pull(true)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pull(false)
		}
	}
}
