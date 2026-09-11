package accessdecision

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// Store is the in-memory access-decision store: recent decisions retained for admin detail lookups and, on the
// hot path, SAME-FLOW event validation — an inspection or tool-call event carries the originating
// AccessDecisionID and is rejected if that decision is not resident (see the ingest handlers).
//
// Lifetime is derived from the originating request, not from a wall-clock timer:
//
//   - While a decision's request is IN FLIGHT it is PINNED and never evicted — the request is demonstrably alive
//     and same-flow events can reference it mid-stream. Pinning is event-driven (MarkInFlight / MarkComplete),
//     with no ceiling: a slow-but-progressing flow (a thin-bandwidth multi-hour download) stays pinned for its
//     whole duration. Release is guaranteed by the caller completing the request — and the transport's own
//     byte-progress idle watchdog reaps a stalled/black-holed connection, which makes the handler complete, so a
//     pin cannot leak. Pins are UNCOUNTED and UNCAPPED; the acceptable concurrent-session count is
//     environment-specific, so it is exposed as a gauge (InFlightCount) for per-deployment alerting, never bounded
//     by a baked-in constant and never dropped.
//   - After completion, an entry becomes unpinned with a completion timestamp and is evicted by IDLE (ttl) — the
//     "event tail" grace for straggler same-flow events; each reference (Get) refreshes it. ttl<=0 disables it.
//   - The FIFO `capacity` bounds the UNPINNED set only (completed / within-grace / legacy Upsert entries) as a
//     hard spike/bug backstop. capacity<=0 disables it. Pinned entries do not count toward it.
type Store struct {
	mu          sync.RWMutex
	entries     map[string]*decisionNode // all decisions, pinned and unpinned
	order       *list.List               // UNPINNED only; front = least-recently-active (seen ascending)
	pinnedCount int
	capacity    int
	ttl         time.Duration
	now         func() time.Time
}

// decisionNode is the map+list payload. seen is the last-activity time (completion, or a later same-flow
// reference) and drives idle eviction; it is meaningful only while unpinned. el is this node's element in the
// unpinned order list, or nil while the node is pinned (in flight) and thus held out of the list.
type decisionNode struct {
	id   string
	dec  model.AccessDecision
	seen time.Time
	el   *list.Element
}

// NewStore builds an access-decision store with the given UNPINNED FIFO capacity and NO idle expiry (ttl=0), for
// back-compat callers. The bounds are injected by cmd/edge (which reads them from the environment) so this
// package stays env-name-free.
func NewStore(capacity int) *Store { return NewStoreWithTTL(capacity, 0) }

// NewStoreWithTTL adds the event-tail grace (idle from completion): an unpinned decision with no activity for ttl
// is evicted on the next mutation (ttl<=0 keeps count-only behaviour). capacity bounds the unpinned set.
func NewStoreWithTTL(capacity int, ttl time.Duration) *Store {
	return &Store{entries: map[string]*decisionNode{}, order: list.New(), capacity: capacity, ttl: ttl, now: time.Now}
}

// Upsert records a decision as UNPINNED (back-compat: creation + immediate eligibility for idle/count eviction).
// Prefer MarkInFlight + MarkComplete for request-scoped decisions so a live flow is never evicted.
func (s *Store) Upsert(dec model.AccessDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putLocked(dec, false)
	s.evictLocked(s.now())
}

// MarkInFlight records/updates a decision as PINNED (its request is in flight): exempt from idle and count
// eviction until MarkComplete. Call once at decision time.
func (s *Store) MarkInFlight(dec model.AccessDecision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putLocked(dec, true)
	s.evictLocked(s.now()) // still reclaim unpinned entries
}

// MarkComplete unpins a decision (its request ended, cleanly or not) and stamps the completion time, starting the
// event-tail grace. Idempotent and safe if the id is unknown (already unpinned / never seen).
func (s *Store) MarkComplete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if node, ok := s.entries[id]; ok {
		if node.el == nil { // was pinned
			node.seen = now
			node.el = s.order.PushBack(node)
			s.pinnedCount--
		} else { // already unpinned: treat completion as activity
			node.seen = now
			s.order.MoveToBack(node.el)
		}
	}
	s.evictLocked(now)
}

// putLocked inserts or updates a node with the requested pinned state. Caller holds s.mu.
func (s *Store) putLocked(dec model.AccessDecision, pinned bool) {
	now := s.now()
	node, ok := s.entries[dec.ID]
	if !ok {
		node = &decisionNode{id: dec.ID, dec: dec}
		s.entries[dec.ID] = node
		if pinned {
			s.pinnedCount++ // held out of order
		} else {
			node.seen = now
			node.el = s.order.PushBack(node)
		}
		return
	}
	node.dec = dec
	switch {
	case pinned && node.el != nil: // unpinned -> pinned
		s.order.Remove(node.el)
		node.el = nil
		s.pinnedCount++
	case pinned && node.el == nil: // stays pinned
		// nothing: pinned entries have no idle clock
	case !pinned && node.el == nil: // pinned -> unpinned
		node.seen = now
		node.el = s.order.PushBack(node)
		s.pinnedCount--
	default: // stays unpinned: refresh activity
		node.seen = now
		s.order.MoveToBack(node.el)
	}
}

// evictLocked reclaims UNPINNED entries: first idle-expired (front prefix, seen-ascending), then the count
// backstop (least-recently-active). Pinned entries are never touched. Caller holds s.mu.
func (s *Store) evictLocked(now time.Time) {
	if s.ttl > 0 {
		cutoff := now.Add(-s.ttl)
		for {
			front := s.order.Front()
			if front == nil || !front.Value.(*decisionNode).seen.Before(cutoff) {
				break
			}
			s.removeUnpinnedLocked(front)
		}
	}
	if s.capacity > 0 {
		for s.order.Len() > s.capacity {
			front := s.order.Front()
			if front == nil {
				break
			}
			s.removeUnpinnedLocked(front)
		}
	}
}

func (s *Store) removeUnpinnedLocked(el *list.Element) {
	node := el.Value.(*decisionNode)
	delete(s.entries, node.id)
	s.order.Remove(el)
}

// Get returns a decision and, if it is unpinned, refreshes its event-tail grace (a same-flow event validating
// against it is activity). A pinned (in-flight) decision is returned untouched — it is already exempt.
func (s *Store) Get(id string) (model.AccessDecision, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.entries[id]
	if !ok {
		return model.AccessDecision{}, false
	}
	if node.el != nil { // unpinned: reference refreshes the grace
		node.seen = s.now()
		s.order.MoveToBack(node.el)
	}
	return node.dec, true
}

// SnapshotByTenant returns the tenant's retained decisions (pinned and unpinned). Order is not significant — the
// aiops consumers re-sort by the decision's own Timestamp.
func (s *Store) SnapshotByTenant(tenantID string) []model.AccessDecision {
	tenantID = strings.TrimSpace(tenantID)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.AccessDecision, 0, len(s.entries))
	for _, node := range s.entries {
		if strings.TrimSpace(node.dec.TenantID) == tenantID {
			out = append(out, node.dec)
		}
	}
	return out
}

func (s *Store) LatestForApplication(tenantID, applicationID string) (model.AccessDecision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var latest model.AccessDecision
	found := false
	for _, node := range s.entries {
		dec := node.dec
		if strings.TrimSpace(dec.TenantID) != tenantID || strings.TrimSpace(dec.ApplicationID) != applicationID {
			continue
		}
		if !found || accessDecisionAfter(dec, latest) {
			latest = dec
			found = true
		}
	}
	return latest, found
}

func accessDecisionAfter(candidate, current model.AccessDecision) bool {
	candidateTime, candidateErr := time.Parse(time.RFC3339, strings.TrimSpace(candidate.Timestamp))
	currentTime, currentErr := time.Parse(time.RFC3339, strings.TrimSpace(current.Timestamp))
	if candidateErr == nil && currentErr == nil && !candidateTime.Equal(currentTime) {
		return candidateTime.After(currentTime)
	}
	if strings.TrimSpace(candidate.Timestamp) != strings.TrimSpace(current.Timestamp) {
		return strings.TrimSpace(candidate.Timestamp) > strings.TrimSpace(current.Timestamp)
	}
	return candidate.ID > current.ID
}

// Count is the total resident decisions (pinned + unpinned).
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// InFlightCount is the number of pinned (in-flight) decisions — a gauge for per-environment concurrency alerting.
func (s *Store) InFlightCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pinnedCount
}

// Capacity returns the configured UNPINNED FIFO capacity bound (<=0 means unbounded).
func (s *Store) Capacity() int { return s.capacity }
