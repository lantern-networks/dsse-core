package main

import (
	"sort"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
)

const adminStandbyAuditInterval = time.Minute

// One collector belongs to one server, across all its admin routes/listeners.
// Keys are registered permissions, never request paths, addresses or credentials.
// The first refusal is immediate; later refusals accumulate until the next allowed
// write. A failed append consumes the same budget as a successful one, including
// its error reporting, so a broken disk does not become a stderr amplification path.
// restart-durability: bounded_buffer — pending refusal counts only, one bucket per
// registered permission. Due within 60–65 seconds absent slow I/O, with a final
// flush on normal process return. Abrupt exit can lose the pending tail. Emitted
// audit records belong to JSONL storage; no published record is rebuilt here.
// populated-by: side_effect — the pre-authentication standby refusal path adds
// observations. This buffer is not authoritative configuration or served state.
type adminStandbyAudit struct {
	mu        sync.Mutex
	writer    *logs.Writer
	evaluator decision.Evaluator
	now       func() time.Time
	buckets   map[string]*adminStandbyAuditBucket
}

type adminStandbyAuditBucket struct {
	permission        string
	count             uint64
	first, last, next time.Time
}

func newAdminStandbyAudit(writer *logs.Writer, evaluator decision.Evaluator) *adminStandbyAudit {
	return &adminStandbyAudit{writer: writer, evaluator: evaluator, now: time.Now, buckets: make(map[string]*adminStandbyAuditBucket)}
}

// Called while registering routes, not when processing untrusted input. Repeated
// routes with the same permission share the same counter and write budget.
func (a *adminStandbyAudit) forPermission(permission string) func() {
	if !adminPermissionWrites(permission) {
		return func() {}
	}
	a.mu.Lock()
	b := a.buckets[permission]
	if b == nil {
		b = &adminStandbyAuditBucket{permission: permission}
		a.buckets[permission] = b
	}
	a.mu.Unlock()
	return func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		now := a.now()
		if b.count == 0 {
			b.first = now
		}
		b.last = now
		b.count++
		if !now.Before(b.next) {
			a.emit(b, now)
		}
	}
}

// Caller holds mu. Counts describe this attempt, not confirmed durability. Do not
// retry a failed batch: an append-hook failure can follow a successful primary
// write, and replay would count the same requests twice. Writer health and the
// bounded process error report expose uncertainty instead.
func (a *adminStandbyAudit) emit(b *adminStandbyAuditBucket, now time.Time) {
	if b.count == 0 {
		return
	}
	recordAdminStandbyRefusal(a.writer, a.evaluator, b.permission, now, b.first, b.last, b.count)
	b.count = 0
	b.next = now.Add(adminStandbyAuditInterval)
}

func (a *adminStandbyAudit) flush(final bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	keys := make([]string, 0, len(a.buckets))
	for k := range a.buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b := a.buckets[k]
		if final || !now.Before(b.next) {
			a.emit(b, now)
		}
	}
}

// Only main starts the periodic worker. Embedded/test servers can drive flush
// explicitly, without background writes outliving their server or temporary files.
// Ordinary pending batches are attempted within 60–65 seconds of the previous
// attempt, even when requests stop. The returned stop waits for a final flush.
// Abrupt termination can lose the in-memory batch; this is not a durable queue.
func (a *adminStandbyAudit) start() func() {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		a.run(stop, ticker.C)
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stop); <-done }) }
}

func (a *adminStandbyAudit) run(stop <-chan struct{}, ticks <-chan time.Time) {
	for {
		select {
		case <-stop:
			a.flush(true)
			return
		case <-ticks:
			a.flush(false)
		}
	}
}
