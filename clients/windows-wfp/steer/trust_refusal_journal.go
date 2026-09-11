package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// trust_refusal_journal.go — why a device declined to trust its Edge, kept until someone can be told.
//
// A device that refuses the Edge's certificate cannot report that it refused: the report travels over the very
// (T) connection it just declined to make. From the Edge and the Console a fleet refusing a certificate and a
// fleet switched off look identical — the one signal that separates them lives only in each device's own log.
// That is why the 2026-07-31 outage was unexplainable for 47 minutes.
//
// So refusals are written down locally and shipped on the next connection that DOES succeed. Late by definition,
// and late is the only option; the alternative is never. Mirrors the macOS DsseTrustRefusalJournal exactly so
// one description covers both clients and the Edge merges them the same way. Nothing here is secret: a
// fingerprint and a verifier's error string about a certificate the Edge served publicly.

const (
	maxRefusalEntries   = 32  // distinct (certificate, reason) pairs — the count field absorbs retries
	maxRefusalReasonLen = 300 // a verifier string, not an essay
)

// trustRefusal is one (served certificate, reason) pair and how many handshakes it covers. The JSON shape is the
// Edge contract, shared with the macOS client.
type trustRefusal struct {
	ServedSHA256 string `json:"served_sha256"` // sha256 of the leaf the Edge presented ("" if it sent none)
	Reason       string `json:"reason"`        // the verifier's own words, NOT classified into a code
	FirstAt      string `json:"first_at"`      // RFC3339
	LastAt       string `json:"last_at"`       // RFC3339
	Count        int    `json:"count"`
}

// key identifies a refusal for the clear-after-accept step. It INCLUDES the count on purpose: an entry that
// recurred while a report was in flight has a higher count, a different key, and is therefore kept rather than
// dropped — the copy the Edge acknowledged is gone, but what happened since is not.
func (r trustRefusal) key() string {
	return r.ServedSHA256 + "\x01" + r.Reason + "\x01" + strconv.Itoa(r.Count)
}

// trustRefusalJournal is the bounded, file-backed store. In-memory is the source of truth (fast record on the
// handshake path); the file is a write-through so a refusal survives the restart of a device that is failing to
// connect. Every method is nil-safe and best-effort: a journal problem must NEVER break a handshake further.
type trustRefusalJournal struct {
	mu      sync.Mutex
	path    string
	entries []trustRefusal
	// onRefusal, when set, is called every time a refusal is recorded — the signal that this device cannot
	// verify the Edge right now.
	//
	// ★ THE ONE FAILURE WHERE SPEED MATTERS IS THE ONE WHERE THE FAST PATH IS DEAD (2026-08-20, measured on
	// win-dev-1). Trust-anchor recovery learns about a newer distribution from a header on the response to the
	// report this agent sends every minute — and that report rides the (T) transport. When the transport stops
	// verifying, the report stops, so the hint stops, and the device falls back to a six-hour timer at exactly
	// the moment it is dark and fail-open. This box sat unprotected for 31 minutes on a distribution that had
	// already been corrected upstream, and only a person restarting a service ended it.
	//
	// A refusal is the device saying "I cannot verify the Edge", which is precisely the condition the recovery
	// path exists for, so it wakes that path directly rather than through a channel that is down.
	onRefusal func()
}

// newTrustRefusalJournal loads any persisted refusals from stateDir. Empty stateDir => nil journal (disabled),
// so a deployment with no on-disk state dir simply does not record — and every call below tolerates nil.
func newTrustRefusalJournal(stateDir string) *trustRefusalJournal {
	if stateDir == "" {
		return nil
	}
	j := &trustRefusalJournal{path: filepath.Join(stateDir, "trust_refusals.json")}
	if raw, err := os.ReadFile(j.path); err == nil {
		_ = json.Unmarshal(raw, &j.entries)
	}
	return j
}

// record folds a refusal into the journal, merging with an existing (certificate, reason) pair so a device that
// retries hard produces one growing count rather than thousands of lines.
func (j *trustRefusalJournal) record(leafDER []byte, reason string, now time.Time) {
	if j == nil {
		return
	}
	fingerprint := ""
	if len(leafDER) > 0 {
		sum := sha256.Sum256(leafDER)
		fingerprint = hex.EncodeToString(sum[:])
	}
	if len(reason) > maxRefusalReasonLen {
		reason = reason[:maxRefusalReasonLen]
	}
	ts := now.UTC().Format(time.RFC3339)
	if j.onRefusal != nil {
		j.onRefusal()
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.entries {
		if j.entries[i].ServedSHA256 == fingerprint && j.entries[i].Reason == reason {
			j.entries[i].LastAt = ts
			j.entries[i].Count++
			j.persistLocked()
			return
		}
	}
	j.entries = append(j.entries, trustRefusal{
		ServedSHA256: fingerprint, Reason: reason, FirstAt: ts, LastAt: ts, Count: 1,
	})
	// Oldest first out: a device that has refused for a while already said the important thing in its earliest
	// entries, but the newest describe what is happening NOW.
	if len(j.entries) > maxRefusalEntries {
		j.entries = append([]trustRefusal(nil), j.entries[len(j.entries)-maxRefusalEntries:]...)
	}
	j.persistLocked()
}

// pending returns a copy of what has not been reported and accepted yet.
func (j *trustRefusalJournal) pending() []trustRefusal {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.entries) == 0 {
		return nil
	}
	return append([]trustRefusal(nil), j.entries...)
}

// clear drops entries ONLY after the Edge has accepted them (a 2xx on the report). Clearing on send would lose
// exactly the reports that matter, since the send is happening over a connection that only just came back. An
// entry whose count grew while the report was in flight has a different key and is deliberately kept.
func (j *trustRefusalJournal) clear(reported []trustRefusal) {
	if j == nil || len(reported) == 0 {
		return
	}
	sent := make(map[string]struct{}, len(reported))
	for _, r := range reported {
		sent[r.key()] = struct{}{}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	var kept []trustRefusal
	for _, e := range j.entries {
		if _, acked := sent[e.key()]; !acked {
			kept = append(kept, e)
		}
	}
	j.entries = kept
	j.persistLocked()
}

func (j *trustRefusalJournal) persistLocked() {
	raw, err := json.Marshal(j.entries)
	if err != nil {
		return
	}
	tmp := j.path + ".tmp"
	if os.WriteFile(tmp, raw, 0o644) == nil {
		_ = os.Rename(tmp, j.path)
	}
}
