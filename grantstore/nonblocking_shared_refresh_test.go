package grantstore

import (
	"sync/atomic"
	"testing"
	"time"
)

type heldSharedRead struct {
	grantSharedFixture
	hold    atomic.Bool
	loads   atomic.Int64
	entered chan struct{}
	release chan struct{}
}

func (p *heldSharedRead) Load() ([]byte, error) {
	raw, e := p.grantSharedFixture.Load()
	if p.hold.Load() {
		p.loads.Add(1)
		p.entered <- struct{}{}
		<-p.release
	}
	return raw, e
}
func waitRefreshDone(t *testing.T, s *Store) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		s.readRefreshMu.Lock()
		busy := s.readRefreshRunning
		s.readRefreshMu.Unlock()
		if !busy {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("refresh did not finish")
}
func TestSharedRefreshHasNoDataPathWaitAndKeepsFiveSecondFreshnessBound(t *testing.T) {
	p := &heldSharedRead{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s := NewStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	if _, e := s.Mint(grantFixture("grant", now), time.Hour, now); e != nil {
		t.Fatal(e)
	}
	p.hold.Store(true)
	s.mu.Lock()
	s.readRefreshAt = time.Now().Add(-3 * time.Second)
	s.mu.Unlock()
	if !s.ValidForAuthorization("grant", now) {
		t.Fatal("still-fresh confirmed snapshot was denied")
	}
	select {
	case <-p.entered:
	case <-time.After(time.Second):
		t.Fatal("proactive read not started")
	}
	check := func(want bool) {
		t.Helper()
		done := make(chan bool, 8)
		for i := 0; i < 8; i++ {
			go func() { done <- s.ValidForAuthorization("grant", now) }()
		}
		for i := 0; i < 8; i++ {
			select {
			case got := <-done:
				if got != want {
					t.Error("freshness boundary violated")
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("data-path call waited for shared I/O")
			}
		}
	}
	check(true)
	s.mu.Lock()
	s.readRefreshAt = time.Now().Add(-6 * time.Second)
	s.mu.Unlock()
	check(false)
	if p.loads.Load() != 1 {
		t.Error("readers started duplicate refresh workers")
	}
	p.hold.Store(false)
	close(p.release)
	waitRefreshDone(t, s)
	if !s.ValidForAuthorization("grant", now) {
		t.Fatal("successful refresh did not restore confirmed authorization")
	}
}

func TestOldSharedReadCannotUndoAConcurrentConfirmedRevocation(t *testing.T) {
	p := &heldSharedRead{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s := NewStore()
	s.SetPersister(p)
	now := time.Now().UTC()
	g, e := s.Mint(grantFixture("grant", now), time.Hour, now)
	if e != nil {
		t.Fatal(e)
	}
	p.hold.Store(true)
	s.mu.Lock()
	s.readRefreshAt = time.Now().Add(-3 * time.Second)
	s.mu.Unlock()
	s.ValidForAuthorization(g.GrantID, now)
	<-p.entered
	if _, _, e = s.RevokeForTenant(g.TenantID, g.GrantID); e != nil {
		t.Fatal(e)
	}
	p.hold.Store(false)
	close(p.release)
	waitRefreshDone(t, s)
	if s.ValidForAuthorization(g.GrantID, now) {
		t.Fatal("pre-revocation read overwrote a newer denial")
	}
}

func TestCheckedSnapshotSerializesLocalWritesWithoutBlockingAuthorization(t *testing.T) {
	for _, generationOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "rows", true: "generation"}[generationOnly], func(t *testing.T) {
			p := &heldSharedRead{entered: make(chan struct{}, 1), release: make(chan struct{})}
			s := NewStore()
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			if _, err := s.Mint(grantFixture("existing", now), time.Hour, now); err != nil {
				t.Fatal(err)
			}
			before := s.ConfigGeneration()
			p.hold.Store(true)
			done := make(chan error, 1)
			go func() {
				var generation uint64
				var err error
				if generationOnly {
					generation, err = s.SnapshotGenerationChecked()
				} else {
					var rows []Grant
					rows, generation, err = s.SnapshotAllChecked()
					if err == nil && (len(rows) != 1 || rows[0].GrantID != "existing") {
						t.Error("snapshot rows were changed by concurrent writer")
					}
				}
				if err == nil && generation != before {
					t.Error("snapshot generation differs from captured rows")
				}
				done <- err
			}()
			<-p.entered
			minted := make(chan error, 1)
			go func() { _, err := s.Mint(grantFixture("new", now), time.Hour, now); minted <- err }()
			read := make(chan bool, 1)
			go func() { read <- s.ValidForAuthorization("existing", now) }()
			select {
			case valid := <-read:
				if !valid {
					t.Error("fresh authorization lost while snapshot loads")
				}
			case <-time.After(250 * time.Millisecond):
				t.Error("snapshot blocked authorization on shared I/O")
			}
			mintFinished := false
			select {
			case <-minted:
				mintFinished = true
				t.Error("writer changed the snapshot before capture")
			default:
			}
			p.hold.Store(false)
			close(p.release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !mintFinished {
				if err := <-minted; err != nil {
					t.Fatal(err)
				}
			}
			if !s.ValidForAuthorization("new", now) || s.ConfigGeneration() <= before {
				t.Fatal("writer did not resume after snapshot capture")
			}
		})
	}
}

func TestExpiredSharedReadDoesNotWaitForAnInFlightCommit(t *testing.T) {
	p := &blockedSharedCommit{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s := NewStore()
	s.SetPersister(p)
	now := time.Now().UTC()
	s.Mint(grantFixture("existing", now), time.Hour, now)
	p.mu.Lock()
	p.block = true
	p.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, e := s.Mint(grantFixture("new", now), time.Hour, now); done <- e }()
	<-p.entered
	s.mu.Lock()
	s.readRefreshAt = time.Now().Add(-6 * time.Second)
	s.mu.Unlock()
	calls := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		go func() { calls <- s.ValidForAuthorization("existing", now) }()
	}
	for i := 0; i < 8; i++ {
		select {
		case allowed := <-calls:
			if allowed {
				t.Error("expired shared authority was used")
			}
		case <-time.After(250 * time.Millisecond):
			t.Error("authorization queued behind the writer")
		}
	}
	close(p.release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	waitRefreshDone(t, s)
	if !s.ValidForAuthorization("new", now) {
		t.Fatal("confirmed commit did not publish a fresh allowance")
	}
}
