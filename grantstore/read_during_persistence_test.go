package grantstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type blockedGrantSave struct {
	mu      sync.Mutex
	raw     []byte
	entered chan struct{}
	release chan struct{}
	block   bool
	fail    bool
}

func (p *blockedGrantSave) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.raw...), nil
}
func (p *blockedGrantSave) Save(raw []byte) error {
	p.mu.Lock()
	block, fail := p.block, p.fail
	p.mu.Unlock()
	if block {
		p.entered <- struct{}{}
		<-p.release
	}
	if fail {
		return errors.New("save refused")
	}
	p.mu.Lock()
	p.raw = append([]byte(nil), raw...)
	p.mu.Unlock()
	return nil
}

func TestAuthorizationContinuesDuringSlowGrantPersistence(t *testing.T) {
	for _, deny := range []bool{false, true} {
		t.Run(map[bool]string{false: "mint", true: "failed-revocation"}[deny], func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			p := &blockedGrantSave{entered: make(chan struct{}, 1), release: make(chan struct{})}
			s := NewStore()
			if e := s.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			g, e := s.Mint(grantFixture("existing", now), time.Hour, now)
			if e != nil {
				t.Fatal(e)
			}
			p.mu.Lock()
			p.block, p.fail = true, deny
			p.mu.Unlock()
			done := make(chan error, 1)
			go func() {
				if deny {
					_, _, e := s.RevokeForTenant(g.TenantID, g.GrantID)
					done <- e
				} else {
					_, e := s.Mint(grantFixture("new", now), time.Hour, now)
					done <- e
				}
			}()
			select {
			case <-p.entered:
			case <-time.After(time.Second):
				t.Fatal("save did not begin")
			}
			read := make(chan bool, 1)
			go func() { read <- s.ValidForAuthorization(g.GrantID, now) }()
			select {
			case allowed := <-read:
				if allowed == deny {
					t.Error("published authorization or denial was lost")
				}
			case <-time.After(250 * time.Millisecond):
				t.Error("authorization was blocked by snapshot I/O")
			}
			if !deny {
				if _, ok := s.GetForAuthorization("new"); ok {
					t.Error("uncommitted mint became visible")
				}
			}
			close(p.release)
			e = <-done
			if (e != nil) != deny {
				t.Fatal(e)
			}
		})
	}
}

func TestExpiredFenceCompactsPayloadWithoutLosingFreshnessBoundary(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := NewStore()
	g := rollingGrant("fence", now)
	g.UserEmail = "fixture@example.test"
	g.Username = "fixture"
	g.AMR = []string{"webauthn"}
	g.AuthTime = now.Add(-time.Minute).Format(time.RFC3339)
	if _, e := s.Mint(g, time.Minute, now); e != nil {
		t.Fatal(e)
	}
	if _, _, e := s.RequireReauthenticationForTenantContext(nil, g.TenantID, g.GrantID, now); e != nil {
		t.Fatal(e)
	}
	before := s.grants[g.GrantID]
	later := now.Add(time.Hour)
	if _, e := s.PruneExpired(nil, later); e != nil {
		t.Fatal(e)
	}
	after := s.grants[g.GrantID]
	if after.UserEmail != "" || len(after.AMR) != 0 || after.ReauthenticateAfter != before.ReauthenticateAfter || fenceSelector(after) != fenceSelector(before) || validateGrant(after) != nil {
		t.Fatal("compact record lost selectors or cutoff")
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if len(b) >= len(a) {
		t.Fatal("expired personal payload was not reduced")
	}
	g.GrantID = "replacement"
	if _, e := s.Mint(g, time.Minute, later); !errors.Is(e, ErrReauthenticationRequired) {
		t.Fatal("compaction allowed old SSO", e)
	}
}

func TestWriterGateDoesNotLoseConcurrentRevocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	p := &blockedGrantSave{entered: make(chan struct{}, 2), release: make(chan struct{})}
	s := NewStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	g, e := s.Mint(grantFixture("existing", now), time.Hour, now)
	if e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	p.block = true
	p.mu.Unlock()
	mint := make(chan error, 1)
	go func() { _, e := s.Mint(grantFixture("other", now), time.Hour, now); mint <- e }()
	<-p.entered
	revoke := make(chan error, 1)
	go func() { _, _, e := s.RevokeForTenant(g.TenantID, g.GrantID); revoke <- e }()
	close(p.release)
	if e := <-mint; e != nil {
		t.Fatal(e)
	}
	if e := <-revoke; e != nil {
		t.Fatal(e)
	}
	restored := NewStore()
	if e := restored.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if restored.Valid(g.GrantID, now) || !restored.Valid("other", now) {
		t.Fatal("serialized writer lost a grant or durable revocation")
	}
}

func TestFenceCompactionDoesNotRewriteUnknownEvidence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, unknown := range []bool{false, true} {
		s := NewStore()
		g := rollingGrant("fence", now)
		g.IssuedAt = now.Add(-time.Hour).Format(time.RFC3339)
		g.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339)
		g.Revoked = true
		g.ReauthenticateAfter = g.IssuedAt
		g.UserEmail = "keep@example.test"
		if unknown {
			g.UnknownFields = map[string]json.RawMessage{"future": json.RawMessage(`{"required":true}`)}
		} else {
			g.RequiredFeatures = append(g.RequiredFeatures, "future-required-feature")
		}
		s.grants[g.GrantID] = cloneGrant(g)
		s.rebuildReauthenticationIndexLocked()
		if _, e := s.PruneExpired(nil, now.Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		a, _ := json.Marshal(s.grants[g.GrantID])
		b, _ := json.Marshal(g)
		if string(a) != string(b) {
			t.Fatal("future evidence was compacted by an old reader")
		}
	}
}

func TestFenceCompactionThresholdIsExplicitAndDoesNotRejectRevocation(t *testing.T) {
	for _, limit := range []string{"0", "2"} {
		t.Run(limit, func(t *testing.T) {
			t.Setenv("DSSE_REAUTHENTICATION_FENCE_COMPACTION_THRESHOLD", limit)
			s := NewStore()
			now := time.Now().UTC().Truncate(time.Second)
			for i := 0; i < 3; i++ {
				g := rollingGrant(fmt.Sprint("grant", i), now)
				g.UserID = fmt.Sprint("subject", i)
				if _, e := s.Mint(g, time.Minute, now); e != nil {
					t.Fatal(e)
				}
				if _, ok, e := s.RequireReauthenticationForTenantContext(nil, g.TenantID, g.GrantID, now); e != nil || !ok {
					t.Fatal(e)
				}
			}
			if limit == "0" && s.fences.count("tenant") != 3 {
				t.Fatal("explicit zero still broadened boundaries")
			}
			if limit == "2" && s.fences.count("tenant") != 1 {
				t.Fatal("configured threshold did not consolidate")
			}
		})
	}
}

type blockedSharedCommit struct {
	grantSharedFixture
	entered, release chan struct{}
	block            bool
}

func (p *blockedSharedCommit) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, e := f(p.raw)
	if e != nil {
		return e
	}
	if p.block {
		p.entered <- struct{}{}
		<-p.release
	}
	if p.fail {
		return errors.New("commit refused")
	}
	p.raw = append([]byte(nil), raw...)
	return nil
}

func TestSharedSlowCommitPublishesDenialsButNotNewAllows(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprint(revoke), func(t *testing.T) {
			p := &blockedSharedCommit{entered: make(chan struct{}, 1), release: make(chan struct{})}
			s := NewStore()
			if e := s.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			now := time.Now().UTC().Truncate(time.Second)
			a, e := s.Mint(grantFixture("existing", now), time.Hour, now)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.Mint(grantFixture("unrelated", now), time.Hour, now); e != nil {
				t.Fatal(e)
			}
			if !s.ValidForAuthorization(a.GrantID, now) {
				t.Fatal("fixture not authorized")
			}
			p.mu.Lock()
			p.block = true
			p.fail = revoke
			p.mu.Unlock()
			done := make(chan error, 1)
			go func() {
				if revoke {
					_, _, e := s.RevokeForTenant(a.TenantID, a.GrantID)
					done <- e
				} else {
					_, e := s.Mint(grantFixture("new", now), time.Hour, now)
					done <- e
				}
			}()
			<-p.entered
			read := make(chan bool, 1)
			go func() {
				read <- s.ValidForAuthorization("unrelated", now) && s.ValidForAuthorization(a.GrantID, now) != revoke && !s.ValidForAuthorization("new", now)
			}()
			select {
			case ok := <-read:
				if !ok {
					t.Error("uncommitted allow or missing denial")
				}
			case <-time.After(250 * time.Millisecond):
				t.Error("cached authorization blocked behind commit I/O")
			}
			close(p.release)
			e = <-done
			if (e != nil) != revoke {
				t.Fatal(e)
			}
		})
	}
}
