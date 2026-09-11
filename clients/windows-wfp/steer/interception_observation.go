package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// interception_observation.go — a device that cannot verify what interception is serving it says so.
//
// WHAT IS MISSING WITHOUT THIS. The (T) transport journals its refusals (trust_refusal_journal.go) and wakes
// anchor recovery, so a device that cannot verify the EDGE is visible. Interception has had nothing. On
// 2026-08-21 this deployment served intercepted certificates under material the announcement did not explain,
// and for eighteen minutes win-dev-1 reported `enforcement=healthy (filters=6/6)` every fifteen seconds with an
// empty refusal journal while every HTTPS request its user made failed. The agent had no opinion about the
// certificates it was steering traffic into, so there was nothing to report.
//
// ★ POSTURE: OBSERVE AND REPORT. TRAFFIC IS NOT TOUCHED. Two alternatives were considered and are ruled out by
// rules this deployment already has, not by preference (Mac, 2026-08-21):
//
//   - Letting the destination bypass interception when it cannot be verified is FAIL-OPEN ON A CONTROL-PLANE
//     PATH. Fail-open here is an install-time decision only; a runtime one is not ours to make.
//   - Blocking the destination is an AUTOMATIC KILL, which this deployment forbids outright.
//
// So the device keeps passing traffic exactly as before and gains the ability to say what it is seeing. Anyone
// reading this later and wondering whether reporting-only was the lazy option: it is the option the rules leave.
//
// ★★ WHAT THIS DELIBERATELY DOES NOT DO, AND WHY — THE FLOW-SHAPE SIGNAL DOES NOT EXIST. The first version of
// this file inferred the failure from flow accounting: a process whose flows all ended just after the
// certificate arrived was reported. It was a good idea (Mac's, letter 74) and the box's own log refuted it.
// Replayed over 46,344 real `steer_flow_end` lines (reproduce with: grep steer_flow_end on the agent log), every rule tried
// produced ~32 findings a day, almost all of them one HTTP/2 API client while it was working perfectly:
//
//	working    app_to_edge=605  edge_to_app=1949    <- a small API response that SUCCEEDED
//	outage     app_to_edge=605  edge_to_app=2365    <- a certificate that was REFUSED
//
// A pooling HTTP/2 client opens far more connections than it uses, an ordinary API reply is about the size of a
// certificate chain, and neither duration nor "did anything complete" separates them. There is no threshold in
// those numbers, and a journal that is wrong thirty times a day is worse than no journal. So the agent stops
// guessing from traffic and ASKS instead: it opens one flow of its own through the same mux and verifies the
// chain it is handed. One handshake per interval, a definite answer, no heuristics — see interception_probe.go.

const (
	// How often the device asks. One handshake at this interval is nothing next to the traffic it is already
	// carrying, and it bounds how long an interception failure can be invisible.
	interceptionProbeInterval = 15 * time.Minute
	// The first probe runs sooner than the interval so a device that boots into a broken deployment says so
	// while somebody is still watching it start.
	interceptionFirstProbeDelay = 2 * time.Minute

	maxInterceptionEntries = 32
	// Twice the transport journal's bound, and the difference is deliberate. A transport refusal carries ONE
	// verifier's sentence; an entry here can carry two of them plus what the probe could not check, and
	// truncating that reproduces exactly the flattening this whole path exists to prevent — the tail is where
	// the second verifier's disagreement lives.
	maxInterceptionReasonLen = 600
)

// interceptionRefusal is one verification this device performed on the certificates interception is serving it.
// The JSON shape deliberately mirrors trustRefusal so the two journals merge the same way.
type interceptionRefusal struct {
	// Destination is the authority the probe used — one of this device's own recent destinations, so the answer
	// is about traffic that actually happens here rather than about a synthetic target.
	Destination string `json:"destination,omitempty"`
	// ServedSHA256 identifies the leaf that was judged, so two devices reporting the same sentence can be shown
	// to be talking about the same certificate (or not).
	ServedSHA256 string `json:"served_sha256,omitempty"`
	// Reason is the verifier's own words — including "x509: ... path length constraint exceeded", which is
	// exactly the sentence that was needed and missing on 2026-08-21. NOT classified into a code: implementations
	// disagree about certificates, and the disagreement is the information.
	Reason string `json:"reason"`

	FirstAt string `json:"first_at"`
	LastAt  string `json:"last_at"`
	Count   int    `json:"count"`
}

// key mirrors trustRefusal.key, including the count for the same reason: an entry that grew while a report was
// in flight is a different entry and is kept rather than dropped.
func (r interceptionRefusal) key() string {
	return r.ServedSHA256 + "\x01" + r.Reason + "\x01" + strconv.Itoa(r.Count)
}

// interceptionRefusalJournal is the bounded, file-backed store, shaped exactly like trustRefusalJournal. Every
// method is nil-safe and best-effort: this must never be able to affect a flow.
type interceptionRefusalJournal struct {
	mu      sync.Mutex
	path    string
	entries []interceptionRefusal
}

// newInterceptionRefusalJournal loads any persisted entries from stateDir. Empty stateDir => nil (disabled).
func newInterceptionRefusalJournal(stateDir string) *interceptionRefusalJournal {
	if stateDir == "" {
		return nil
	}
	j := &interceptionRefusalJournal{path: filepath.Join(stateDir, "interception_refusals.json")}
	if raw, err := os.ReadFile(j.path); err == nil {
		_ = json.Unmarshal(raw, &j.entries)
	}
	return j
}

// record folds one verification in, merging on (certificate, reason) so a device that probes every quarter hour
// against a deployment that stays broken produces one growing count rather than a row per probe.
func (j *interceptionRefusalJournal) record(e interceptionRefusal, now time.Time) {
	if j == nil {
		return
	}
	if len(e.Reason) > maxInterceptionReasonLen {
		e.Reason = e.Reason[:maxInterceptionReasonLen]
	}
	ts := now.UTC().Format(time.RFC3339)
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.entries {
		if j.entries[i].ServedSHA256 == e.ServedSHA256 && j.entries[i].Reason == e.Reason {
			j.entries[i].LastAt = ts
			j.entries[i].Count++
			j.persistLocked()
			return
		}
	}
	e.FirstAt, e.LastAt, e.Count = ts, ts, 1
	j.entries = append(j.entries, e)
	// Oldest first out, for the reason the transport journal gives: the earliest entries already said the
	// important thing, the newest describe what is happening now.
	if len(j.entries) > maxInterceptionEntries {
		j.entries = append([]interceptionRefusal(nil), j.entries[len(j.entries)-maxInterceptionEntries:]...)
	}
	j.persistLocked()
}

func (j *interceptionRefusalJournal) pending() []interceptionRefusal {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.entries) == 0 {
		return nil
	}
	return append([]interceptionRefusal(nil), j.entries...)
}

// clear drops entries only after the Edge accepted them, exactly as the transport journal does.
func (j *interceptionRefusalJournal) clear(reported []interceptionRefusal) {
	if j == nil || len(reported) == 0 {
		return
	}
	sent := make(map[string]struct{}, len(reported))
	for _, r := range reported {
		sent[r.key()] = struct{}{}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	var kept []interceptionRefusal
	for _, e := range j.entries {
		if _, acked := sent[e.key()]; !acked {
			kept = append(kept, e)
		}
	}
	j.entries = kept
	j.persistLocked()
}

func (j *interceptionRefusalJournal) persistLocked() {
	raw, err := json.Marshal(j.entries)
	if err != nil {
		return
	}
	tmp := j.path + ".tmp"
	if os.WriteFile(tmp, raw, 0o644) == nil {
		_ = os.Rename(tmp, j.path)
	}
}

// interceptionWatch probes what interception is serving this device and journals what the verifiers said.
//
// It takes its target from the traffic already going past — noteDestination is called from the flow path and
// does nothing but remember a string. That is the ONLY thing the flow path contributes, deliberately: the flow
// path is where the failed inference used to live (see the note at the top of this file), and all that survives
// of it is "somewhere this device actually talks to", which needs no judgement to be right.
type interceptionWatch struct {
	journal *interceptionRefusalJournal
	// probe returns the leaf fingerprint and the verifiers' sentence for one destination, or ("","") when it
	// could not get an answer. nil = nothing to do.
	probe func(destination string) (leafSHA256, verifierReason string)
	// lastDest is written from the flow path and read by the loop. atomic rather than mutex-guarded because the
	// flow path must not be able to block on this, ever.
	lastDest atomic.Pointer[string]
	logf     func(string, ...any)
	now      func() time.Time
}

func newInterceptionWatch(j *interceptionRefusalJournal, logf func(string, ...any)) *interceptionWatch {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &interceptionWatch{journal: j, logf: logf}
}

// noteDestination remembers one authority this device steered a flow to. Called per flow, so it does the least
// possible: a pointer store. nil-safe.
func (w *interceptionWatch) noteDestination(authority string) {
	if w == nil || authority == "" {
		return
	}
	w.lastDest.Store(&authority)
}

func (w *interceptionWatch) clock() time.Time {
	if w == nil || w.now == nil {
		return time.Now()
	}
	return w.now()
}

// runOnce performs one probe and journals a refusal if there was one. It returns the sentence for tests and for
// the caller's log; "" means no probe happened (nothing steered yet, or no answer could be had).
//
// ★ ONLY A REFUSAL IS JOURNALED. A successful verification is logged and thrown away: the journal is shipped to
// the Edge on every report, and filling it with "everything is fine" every quarter hour would drown the entries
// that matter. The absence of an entry is not evidence of health — the interception-root report beside it
// (interception_root_trust_windows.go) is what says the device is ready — and that asymmetry is the same one the
// transport journal already has.
func (w *interceptionWatch) runOnce() string {
	if w == nil || w.probe == nil {
		return ""
	}
	dp := w.lastDest.Load()
	if dp == nil || *dp == "" {
		return ""
	}
	fingerprint, reason := w.probe(*dp)
	if reason == "" {
		return ""
	}
	if interceptionVerified(reason) {
		w.logf("interception_probe OK dst=%s leaf=%s — this device can verify what interception is serving it", *dp, shortFP(fingerprint))
		return reason
	}
	w.journal.record(interceptionRefusal{Destination: *dp, ServedSHA256: fingerprint, Reason: reason}, w.clock())
	// ★ The line says out loud that nothing was blocked, because the next person to read it will be someone
	// whose HTTPS is failing, and the agent must not be the first suspect when it is not the cause.
	w.logf("★ interception_refusal dst=%s leaf=%s — traffic is NOT being blocked and this changes nothing about "+
		"steering; this device is reporting that it cannot verify what interception is serving it: %s",
		*dp, shortFP(fingerprint), reason)
	return reason
}

// run loops until stop is closed. One goroutine, one handshake per interval.
func (w *interceptionWatch) run(stop <-chan struct{}) {
	if w == nil || w.probe == nil {
		return
	}
	t := time.NewTimer(interceptionFirstProbeDelay)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			w.runOnce()
			t.Reset(interceptionProbeInterval)
		}
	}
}

func shortFP(fp string) string {
	if len(fp) > 16 {
		return fp[:16] + "…"
	}
	return fp
}

// interceptionVerifiedMarker is the one substring that distinguishes the "both verifiers accepted" sentence from
// every refusal sentence. It is checked rather than a boolean being returned alongside because the sentence is
// what travels, and a flag that could disagree with the sentence is a second source of truth.
const interceptionVerifiedMarker = "BOTH verifiers on this device accept it"

func interceptionVerified(reason string) bool {
	return strings.Contains(reason, interceptionVerifiedMarker)
}
