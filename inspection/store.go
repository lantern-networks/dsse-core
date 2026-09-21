package inspection

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
)

// Store is the inspection-event store: SWG decrypt/inspection outcomes (upsert / lookup / per-tenant listing)
// used by the SWG TLS-readiness readback AND the DLP-findings view, FIFO-bounded by capacity (capacity<=0
// disables the bound). In-memory by default; attach a Persister (SetPersister) to make events — notably the
// DLP findings — SURVIVE an Edge restart.
type Store struct {
	mu            sync.RWMutex
	events        map[string]model.InspectionEvent
	order         []string
	capacity      int
	persister     blobstore.Persister
	retention     time.Duration // drop events whose Timestamp is older than this (0 = keep, subject only to the FIFO bound)
	dirty         bool
	sharedKnown   bool
	sharedPending map[string]bool

	// Append-only WAL mode (when the persister supports blobstore.AppendPersister). Under decrypt-all + log-all
	// the store fills fast; re-marshaling the WHOLE snapshot every flush is O(n) memory + I/O and was the cause of
	// an Edge OOM. In append mode, Upsert buffers events and PersistIfDirty APPENDS the batch (O(batch)); the file
	// is compacted (a single full rewrite of the bounded live set) only when it grows past maxWALBytes — so the
	// O(n) marshal is amortized to rare rotations, not every 30s. Durability of the record itself is off-Edge
	// (logs.Writer + domain-event outbox); this file is only a hot-cache WAL so the DLP findings view survives a
	// restart. Shared persisters merge pending IDs into the latest row; other non-append stores use snapshots.
	appendP     blobstore.AppendPersister
	pending     []model.InspectionEvent // events appended since the last flush (append mode only)
	walBytes    int64                   // approximate current WAL size, to trigger compaction
	maxWALBytes int64                   // compact when walBytes exceeds this (0 = derive from capacity)
}

// NewStore builds an inspection-event store with the given FIFO capacity. The bound is injected by
// cmd/edge (which reads it from the environment) so this package stays env-name-free.
func NewStore(capacity int) *Store {
	return &Store{events: map[string]model.InspectionEvent{}, capacity: capacity}
}

// storeSnapshot is the on-disk shape (events + FIFO order) for durability.
type storeSnapshot struct {
	Events map[string]model.InspectionEvent `json:"events"`
	Order  []string                         `json:"order"`
}

// SetPersister attaches durable storage and REHYDRATES the events from it (so the DLP findings view survives a
// restart), dropping any older than retention and re-applying the FIFO bound. Call once at startup. A load error
// is returned but non-fatal. Pair with periodic PersistIfDirty().
func (s *Store) SetPersister(p blobstore.Persister, retention time.Duration) error {
	s.mu.Lock()
	s.persister = p
	s.retention = retention
	if ap, ok := p.(blobstore.AppendPersister); ok {
		s.appendP = ap
		if s.maxWALBytes <= 0 {
			s.maxWALBytes = deriveMaxWALBytes(s.capacity)
		}
	}
	s.mu.Unlock()
	if p == nil {
		return nil
	}
	data, err := p.Load()
	if _, shared := p.(sharedPersister); shared {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.sharedPending = map[string]bool{}
		s.sharedKnown = data != nil || err != nil
		if err != nil {
			return err
		}
		snap, e := decodeSharedSnapshot(data, s.sharedKnown)
		if e != nil {
			return e
		}
		if data != nil {
			s.events, s.order = snap.Events, snap.Order
		} else {
			for id := range s.events {
				s.sharedPending[id] = true
			}
		}
		s.pruneLocked(time.Now())
		s.order = evictFIFO(s.order, len(s.events), s.capacity, func(k string) { delete(s.events, k); delete(s.sharedPending, k) })
		return nil
	}
	if err != nil || len(data) == 0 {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Two on-disk formats coexist: the historical full snapshot ({"events":{...},"order":[...]}) and the
	// append-only WAL (one InspectionEvent JSON per line). Detect the snapshot by its distinctive shape; otherwise
	// replay the WAL (last-write-wins by ID; a torn final line from an interrupted append is skipped). An existing
	// snapshot file thus migrates seamlessly — it loads here and is rewritten as a compacted WAL on the next flush.
	migratedFromSnapshot := false
	if snap, ok := decodeSnapshot(data); ok {
		s.events = snap.Events
		s.order = snap.Order
		migratedFromSnapshot = true
	} else {
		s.replayWALLocked(data)
	}
	s.pruneLocked(time.Now())
	s.order = evictFIFO(s.order, len(s.events), s.capacity, func(k string) { delete(s.events, k); delete(s.sharedPending, k) })
	if s.appendP != nil {
		if migratedFromSnapshot {
			// Convert a legacy snapshot file to WAL (NDJSON) format now, so subsequent appends do not corrupt a
			// mixed snapshot-object + NDJSON file. One-time, at startup, under the lock.
			out := s.encodeWALLocked()
			if err := s.appendP.Save(out); err != nil {
				return err
			}
			s.walBytes = int64(len(out))
		} else if sz, e := s.appendP.Size(); e == nil {
			s.walBytes = sz
		}
	}
	return nil
}

// pruneLocked drops events older than the retention window (by Timestamp). Caller holds the write lock.
func (s *Store) pruneLocked(now time.Time) {
	if s.retention <= 0 {
		return
	}
	cutoff := now.Add(-s.retention)
	kept := s.order[:0]
	for _, id := range s.order {
		ev, ok := s.events[id]
		if !ok {
			continue
		}
		if t, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil && t.Before(cutoff) {
			delete(s.events, id)
			delete(s.sharedPending, id)
			continue
		}
		kept = append(kept, id)
	}
	s.order = append([]string(nil), kept...)
}

// PersistIfDirty flushes unsaved changes. Cheap no-op when clean or when no persister is attached. Call
// periodically — Upsert never does I/O. In APPEND mode (persister supports blobstore.AppendPersister) it appends
// the buffered batch in O(batch), compacting to the bounded live set only when the WAL grows past maxWALBytes; all
// file I/O happens OUTSIDE the lock. Shared transactions merge pending IDs under mu
// (Upsert waits for that bounded transaction); other persisters retain snapshot Save.
func (s *Store) PersistIfDirty() error { return s.PersistIfDirtyContext(context.Background()) }

func (s *Store) PersistIfDirtyContext(ctx context.Context) error {
	s.mu.Lock()
	if s.persister == nil || (!s.dirty && len(s.pending) == 0) {
		s.mu.Unlock()
		return nil
	}
	if p, ok := s.persister.(sharedPersister); ok {
		defer s.mu.Unlock()
		return s.persistSharedLocked(ctx, p)
	}
	if s.appendP != nil {
		// Build the append batch + decide compaction UNDER the lock; do the file write UNLOCKED.
		var batch []byte
		for i := range s.pending {
			if line, err := json.Marshal(s.pending[i]); err == nil {
				batch = append(batch, line...)
				batch = append(batch, '\n')
			}
		}
		s.pending = s.pending[:0]
		s.walBytes += int64(len(batch))
		var compact []byte
		if s.walBytes > s.maxWALBytes {
			// Rotation: prune + FIFO-bound, then rewrite the file to just the live set (which already includes the
			// pending events — they were added to the map on Upsert — so the batch is subsumed and not appended).
			s.pruneLocked(time.Now())
			s.order = evictFIFO(s.order, len(s.events), s.capacity, func(k string) { delete(s.events, k); delete(s.sharedPending, k) })
			compact = s.encodeWALLocked()
		}
		ap := s.appendP
		s.dirty = false
		s.mu.Unlock()
		if compact != nil {
			if err := ap.Save(compact); err != nil { // atomic temp+rename replace
				// The dirty flag was cleared optimistically (the write runs outside the lock). Re-mark dirty
				// so the next flush retries — walBytes is still past the cap, so it re-compacts, which rebuilds
				// the full live set (review #17: a swallowed/dropped failure silently lost the snapshot).
				s.mu.Lock()
				s.dirty = true
				s.mu.Unlock()
				return err
			}
			s.mu.Lock()
			s.walBytes = int64(len(compact))
			s.mu.Unlock()
			return nil
		}
		if len(batch) > 0 {
			if err := ap.Append(batch); err != nil {
				// The batch was already drained from pending, so a failed Append would LOSE those events from
				// the WAL (they live only in memory) until an unrelated compaction. Force the next flush to
				// compact — the live set still contains the batch's events, so the rewrite recovers them.
				s.mu.Lock()
				s.dirty = true
				s.walBytes = s.maxWALBytes + 1
				s.mu.Unlock()
				return err
			}
		}
		return nil
	}
	// Full-snapshot fallback (Postgres blob / any non-append persister).
	s.pruneLocked(time.Now())
	data, err := json.Marshal(storeSnapshot{Events: s.events, Order: s.order})
	p := s.persister
	if err == nil {
		s.dirty = false
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := p.Save(data); err != nil {
		// Same optimistic-clear recovery as the WAL path: stay dirty so the next flush retries.
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
}

// encodeWALLocked renders the live set as NDJSON (one event per line, in FIFO order) — the compacted WAL form.
// Caller holds the write lock.
func (s *Store) encodeWALLocked() []byte {
	var buf []byte
	for _, id := range s.order {
		ev, ok := s.events[id]
		if !ok {
			continue
		}
		if line, err := json.Marshal(ev); err == nil {
			buf = append(buf, line...)
			buf = append(buf, '\n')
		}
	}
	return buf
}

// replayWALLocked rebuilds the map from an NDJSON WAL, last-write-wins by event ID. A line that fails to parse
// (a torn final record from an interrupted append) is skipped, so recovery never fails on a partial tail.
func (s *Store) replayWALLocked(data []byte) {
	s.events = map[string]model.InspectionEvent{}
	s.order = s.order[:0]
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev model.InspectionEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if _, exists := s.events[ev.ID]; !exists {
			s.order = append(s.order, ev.ID)
		}
		s.events[ev.ID] = ev
	}
}

// decodeSnapshot reports whether data is the historical full-snapshot object (vs an NDJSON WAL). A WAL — even a
// one-line one — unmarshals into an InspectionEvent, which has no "events" field, so snap.Events stays nil.
func decodeSnapshot(data []byte) (storeSnapshot, bool) {
	var snap storeSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return storeSnapshot{}, false
	}
	if snap.Events == nil {
		return storeSnapshot{}, false
	}
	return snap, true
}

// deriveMaxWALBytes bounds the WAL to a small multiple of the compacted live set so compaction stays rare while
// disk stays bounded (~4 KB/event heuristic, >=4 MiB floor; a disabled FIFO bound gets a fixed 64 MiB WAL cap).
func deriveMaxWALBytes(capacity int) int64 {
	const perEvent = 4 * 1024
	if capacity <= 0 {
		return 64 * 1024 * 1024
	}
	est := int64(capacity) * perEvent * 3
	if est < 4*1024*1024 {
		est = 4 * 1024 * 1024
	}
	return est
}

func (s *Store) Upsert(event model.InspectionEvent) model.InspectionEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.events[event.ID]; !exists {
		s.order = append(s.order, event.ID)
	}
	s.events[event.ID] = event
	if _, shared := s.persister.(sharedPersister); shared {
		if s.sharedPending == nil {
			s.sharedPending = map[string]bool{}
		}
		s.sharedPending[event.ID] = true
	}
	s.order = evictFIFO(s.order, len(s.events), s.capacity, func(k string) { delete(s.events, k); delete(s.sharedPending, k) })
	s.dirty = true
	if s.appendP != nil {
		// Buffer for the next append flush. Bounded: an event dropped from the buffer is still in the live map, so
		// the next compaction persists it — this only bounds the between-flush memory, never loses a live event.
		s.pending = append(s.pending, event)
		const maxPending = 8192
		if len(s.pending) > maxPending {
			s.pending = append(s.pending[:0], s.pending[len(s.pending)-maxPending:]...)
		}
	}
	return event
}

func (s *Store) Get(id string) (model.InspectionEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	event, ok := s.events[id]
	return event, ok
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// Capacity returns the configured FIFO capacity bound (<=0 means unbounded).
func (s *Store) Capacity() int { return s.capacity }

// ListByTenant returns every event belonging to the given tenant.
func (s *Store) ListByTenant(tenantID string) []model.InspectionEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	events := make([]model.InspectionEvent, 0, len(s.events))
	for _, event := range s.events {
		if strings.TrimSpace(event.TenantID) == tenantID {
			events = append(events, event)
		}
	}
	return events
}

// evictFIFO drops oldest keys until liveLen <= capacity (replicated package-local FIFO bound).
func evictFIFO(order []string, liveLen, capacity int, del func(key string)) []string {
	if capacity <= 0 {
		return order
	}
	for liveLen > capacity && len(order) > 0 {
		oldest := order[0]
		order = order[1:]
		del(oldest)
		liveLen--
	}
	if len(order) > 2*capacity {
		order = append([]string(nil), order...)
	}
	return order
}
