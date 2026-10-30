package inspection

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// countAppendPersister is an in-memory blobstore.AppendPersister that counts Append vs Save (full-rewrite) calls,
// so tests can assert that a normal flush appends (O(batch)) and only compaction rewrites the whole file.
type countAppendPersister struct {
	mu      sync.Mutex
	data    []byte
	appends int
	saves   int
	saveErr error
}

func (p *countAppendPersister) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.data...), nil
}
func (p *countAppendPersister) Save(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saves++
	if p.saveErr != nil {
		return p.saveErr
	}
	p.data = append([]byte(nil), b...)
	return nil
}
func (p *countAppendPersister) Append(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.appends++
	p.data = append(p.data, b...)
	return nil
}
func (p *countAppendPersister) Size() (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return int64(len(p.data)), nil
}

func ev(id, tenant string, at time.Time) model.InspectionEvent {
	return model.InspectionEvent{ID: id, TenantID: tenant, Timestamp: at.Format(time.RFC3339)}
}

// A normal flush APPENDS the batch (O(batch)) and never full-rewrites; findings survive a restart via WAL replay.
func TestAppendModeFlushIsAppendNotRewrite(t *testing.T) {
	p := &countAppendPersister{}
	now := time.Now().UTC()
	s1 := NewStore(0)
	if err := s1.SetPersister(p, 90*24*time.Hour); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	s1.Upsert(ev("e1", "acme", now))
	s1.Upsert(ev("e2", "acme", now))
	if err := s1.PersistIfDirty(); err != nil {
		t.Fatalf("PersistIfDirty: %v", err)
	}
	if p.appends != 1 || p.saves != 0 {
		t.Fatalf("normal flush should append once and never full-rewrite: appends=%d saves=%d", p.appends, p.saves)
	}
	// Restart: rehydrate from the WAL.
	s2 := NewStore(0)
	if err := s2.SetPersister(p, 90*24*time.Hour); err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	if got := s2.ListByTenant("acme"); len(got) != 2 {
		t.Fatalf("after restart got %d events, want 2", len(got))
	}
	if _, ok := s2.Get("e1"); !ok {
		t.Fatal("e1 did not survive restart")
	}
}

// Compaction keeps the WAL bounded no matter how many events churn through, and the FIFO cap holds.
func TestAppendModeCompactionBoundsWAL(t *testing.T) {
	p := &countAppendPersister{}
	now := time.Now().UTC()
	s := NewStore(3) // small live-set cap
	if err := s.SetPersister(p, 0); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	s.maxWALBytes = 300 // force frequent compaction (white-box)
	for i := 0; i < 200; i++ {
		s.Upsert(ev("e"+itoa(i), "acme", now))
		if err := s.PersistIfDirty(); err != nil {
			t.Fatalf("flush %d: %v", i, err)
		}
	}
	sz, _ := p.Size()
	if sz > 4*300 {
		t.Fatalf("WAL not bounded by compaction: size=%d, want <= %d", sz, 4*300)
	}
	if p.saves == 0 {
		t.Fatal("expected at least one compaction (Save) under churn")
	}
	// The live set stays FIFO-capped; a restart yields exactly the last cap events.
	s2 := NewStore(3)
	if err := s2.SetPersister(p, 0); err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	if s2.Count() != 3 {
		t.Fatalf("after restart Count=%d, want 3 (FIFO cap)", s2.Count())
	}
	if _, ok := s2.Get("e199"); !ok {
		t.Fatal("newest event e199 missing after restart")
	}
	if _, ok := s2.Get("e0"); ok {
		t.Fatal("oldest event e0 should have been evicted")
	}
}

// Last-write-wins: re-upserting an ID persists the newer value across a restart.
func TestAppendModeLastWriteWins(t *testing.T) {
	p := &countAppendPersister{}
	now := time.Now().UTC()
	s := NewStore(0)
	if err := s.SetPersister(p, 90*24*time.Hour); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	sev := "low"
	s.Upsert(model.InspectionEvent{ID: "e1", TenantID: "acme", Severity: &sev, Timestamp: now.Format(time.RFC3339)})
	_ = s.PersistIfDirty()
	sev2 := "high"
	s.Upsert(model.InspectionEvent{ID: "e1", TenantID: "acme", Severity: &sev2, Timestamp: now.Format(time.RFC3339)})
	_ = s.PersistIfDirty()
	s2 := NewStore(0)
	if err := s2.SetPersister(p, 90*24*time.Hour); err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	got, ok := s2.Get("e1")
	if !ok || got.Severity == nil || *got.Severity != "high" {
		t.Fatalf("LWW failed: got %+v, want Severity=high", got)
	}
	if s2.Count() != 1 {
		t.Fatalf("Count=%d, want 1 (LWW must not duplicate the ID)", s2.Count())
	}
}

func TestAppendModeSameEventIDRetainsBothTenants(t *testing.T) {
	p := &countAppendPersister{}
	s := NewStore(0)
	if err := s.SetPersister(p, 0); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		s.Upsert(ev("same", tenant, time.Now().UTC()))
	}
	if err := s.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	reloaded := NewStore(0)
	if err := reloaded.SetPersister(p, 0); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		if got, ok := reloaded.GetForTenant(tenant, "same"); !ok || got.TenantID != tenant {
			t.Fatalf("%s event missing after WAL replay: %+v", tenant, got)
		}
	}
}

// A torn final record (crash mid-append) is skipped on replay; earlier events survive.
func TestAppendModeTornTailRecovery(t *testing.T) {
	p := &countAppendPersister{}
	now := time.Now().UTC()
	s := NewStore(0)
	if err := s.SetPersister(p, 90*24*time.Hour); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	s.Upsert(ev("e1", "acme", now))
	s.Upsert(ev("e2", "acme", now))
	_ = s.PersistIfDirty()
	// Simulate an interrupted append: a partial, unterminated JSON line at the tail.
	_ = p.Append([]byte(`{"id":"e3","tenant_id":"acm`))
	s2 := NewStore(0)
	if err := s2.SetPersister(p, 90*24*time.Hour); err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	if s2.Count() != 2 {
		t.Fatalf("Count=%d, want 2 (torn e3 must be skipped)", s2.Count())
	}
	if _, ok := s2.Get("e3"); ok {
		t.Fatal("torn e3 must not load")
	}
	s2.Upsert(ev("e4", "acme", now))
	if err := s2.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	s3 := NewStore(0)
	if err := s3.SetPersister(p, 90*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, ok := s3.Get("e4"); !ok {
		t.Fatal("records appended after torn-tail recovery must survive restart")
	}
}

func TestInvalidLegacySnapshotCannotBecomeEmptyWAL(t *testing.T) {
	original := []byte(`{"events":{"wrong":{"id":"event","tenant_id":"tenant"}},"order":["wrong"]}`)
	p := &countAppendPersister{data: bytes.Clone(original)}
	s := NewStore(0)
	if err := s.SetPersister(p, 0); err == nil {
		t.Fatal("invalid snapshot must fail restoration")
	}
	if s.Count() != 0 {
		t.Fatal("invalid snapshot must not create an empty-identity event")
	}
	s.Upsert(ev("later", "tenant", time.Now().UTC()))
	if err := s.PersistIfDirty(); err == nil {
		t.Fatal("failed restoration must block later overwrite")
	}
	if !bytes.Equal(p.data, original) || p.saves != 0 || p.appends != 0 {
		t.Fatal("failed restoration changed the original snapshot")
	}
}

func TestAppendModePendingOverflowCompactsAllLiveEvents(t *testing.T) {
	p := &countAppendPersister{}
	s := NewStore(0)
	if err := s.SetPersister(p, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 8193; i++ {
		s.Upsert(ev("event-"+itoa(i), "tenant", now))
	}
	if err := s.PersistIfDirty(); err != nil {
		t.Fatal(err)
	}
	if p.saves != 1 {
		t.Fatalf("overflow needs one full rewrite, saves=%d", p.saves)
	}
	reloaded := NewStore(0)
	if err := reloaded.SetPersister(p, 0); err != nil {
		t.Fatal(err)
	}
	if reloaded.Count() != 8193 {
		t.Fatalf("reloaded count=%d, want 8193", reloaded.Count())
	}
	if _, ok := reloaded.GetForTenant("tenant", "event-0"); !ok {
		t.Fatal("event dropped from pending buffer was lost")
	}
}

// A legacy full-snapshot file migrates on load and is rewritten as a WAL, so later appends do not corrupt it.
func TestAppendModeMigratesLegacySnapshot(t *testing.T) {
	p := &countAppendPersister{}
	now := time.Now().UTC()
	// Seed a legacy snapshot ({"events":{...},"order":[...]}).
	snap := storeSnapshot{
		Events: map[string]model.InspectionEvent{"e1": ev("e1", "acme", now)},
		Order:  []string{"e1"},
	}
	p.data, _ = json.Marshal(snap)

	s := NewStore(0)
	if err := s.SetPersister(p, 90*24*time.Hour); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	if _, ok := s.Get("e1"); !ok {
		t.Fatal("legacy e1 did not load")
	}
	if p.saves != 1 {
		t.Fatalf("migration should rewrite the file once (Save), saves=%d", p.saves)
	}
	// Append more, then restart — the file is now WAL and both events load.
	s.Upsert(ev("e2", "acme", now))
	_ = s.PersistIfDirty()
	s2 := NewStore(0)
	if err := s2.SetPersister(p, 90*24*time.Hour); err != nil {
		t.Fatalf("rehydrate after migration: %v", err)
	}
	if s2.Count() != 2 {
		t.Fatalf("after migration+append+restart Count=%d, want 2", s2.Count())
	}
}

func TestFailedLegacySnapshotMigrationCannotAppendMixedFormat(t *testing.T) {
	snap := storeSnapshot{
		Events: map[string]model.InspectionEvent{"e1": ev("e1", "tenant", time.Now().UTC())},
		Order:  []string{"e1"},
	}
	original, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	p := &countAppendPersister{data: bytes.Clone(original), saveErr: errors.New("save failed")}
	s := NewStore(0)
	if err := s.SetPersister(p, 0); err == nil {
		t.Fatal("snapshot migration failure must be returned")
	}
	s.Upsert(ev("e2", "tenant", time.Now().UTC()))
	if err := s.PersistIfDirty(); err == nil {
		t.Fatal("migration failure must block append to snapshot object")
	}
	if p.appends != 0 || !bytes.Equal(p.data, original) {
		t.Fatal("failed migration modified or mixed the original snapshot")
	}
}

// itoa avoids importing strconv just for the churn loop.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
