package authrollout

import (
	"context"
	"testing"
	"time"
)

func TestReceiptLeaseIgnoresCPClockAndReplayCannotRenew(t *testing.T) {
	for _, skew := range []time.Duration{-30 * time.Second, -6 * time.Second, 0, 110 * time.Second, 130 * time.Second} {
		t.Run(skew.String(), func(t *testing.T) {
			s, _, m, cpTime := fixture(t)
			wire, err := s.Distribute(cpTime)
			if err != nil {
				t.Fatal(err)
			}
			db := &memory{}
			c := NewCache(NewStore(db))
			received := cpTime.Add(skew)
			if err = c.Adopt(context.Background(), *wire, received); err != nil {
				t.Fatal(err)
			}
			d, _ := c.Read()
			digest := m.Providers[ProviderKey("tenant", "corp")]
			if !d.AcceptLegacy("tenant", "corp", digest, received.Add(FreshFor-time.Second)) {
				t.Fatal("clock skew shortened receipt lease")
			}
			replay := *wire
			replay.IssuedAt = cpTime.Add(time.Hour)
			replay.ExpiresAt = replay.IssuedAt.Add(FreshFor)
			if err = c.Adopt(context.Background(), replay, received.Add(FreshFor-time.Second)); err != nil {
				t.Fatal(err)
			}
			d, _ = c.Read()
			if d.AcceptLegacy("tenant", "corp", digest, received.Add(FreshFor)) {
				t.Fatal("same revision renewed lease")
			}
			c = NewCache(NewStore(db))
			d, _ = c.Read()
			if d.AcceptLegacy("tenant", "corp", digest, received) {
				t.Fatal("restart restored a lease from wall clock")
			}
			// A new leader may have an earlier wall clock. Revision, not that clock,
			// orders the authoritative state; receipt time supplies the new lease.
			report(t, s, m, 0, cpTime)
			promoted, _ := s.Distribute(cpTime.Add(-time.Minute))
			if err = c.Adopt(context.Background(), *promoted, received.Add(FreshFor)); err != nil {
				t.Fatal(err)
			}
			d, _ = c.Read()
			if !d.AcceptLegacy("tenant", "corp", digest, received.Add(FreshFor)) {
				t.Fatal("new CP clock blocked renewal")
			}
		})
	}
}

func TestCompletionSurvivesOfflineLeaseAndStableReportsDoNotWrite(t *testing.T) {
	s, db, m, now := fixture(t)
	for i := range m.Members {
		report(t, s, m, i, now)
	}
	features := []string{EvidenceFeature, SingleRequestFeature}
	if err := s.Activate(context.Background(), 1, features, now); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Read()
	beforeBytes := string(db.b)
	for i := range m.Members {
		report(t, s, m, i, now.Add(time.Hour))
	}
	if err := s.Activate(context.Background(), 1, features, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Read()
	if after.Revision != before.Revision || string(db.b) != beforeBytes {
		t.Fatal("stable completion reports rewrote authority")
	}
	wire, _ := s.Distribute(now)
	cacheDB := &memory{}
	c := NewCache(NewStore(cacheDB))
	if err := c.Adopt(context.Background(), *wire, now); err != nil {
		t.Fatal(err)
	}
	c = NewCache(NewStore(cacheDB))
	d, _ := c.Read()
	if !d.FeatureEnabled(SingleRequestFeature, now.Add(24*time.Hour)) {
		t.Fatal("CP outage disabled completed capability")
	}
	if d.AcceptLegacy("tenant", "corp", m.Providers[ProviderKey("tenant", "corp")], now) {
		t.Fatal("completion reopened legacy")
	}
}

func TestCompletionSubsetStillAllowsLaterCapabilityActivation(t *testing.T) {
	s, _, m, now := fixture(t)
	for i := range m.Members {
		report(t, s, m, i, now)
	}
	if err := s.Activate(context.Background(), 1, []string{EvidenceFeature}, now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Hour)
	for i := range m.Members {
		report(t, s, m, i, later)
	}
	if err := s.Activate(context.Background(), 1, []string{EvidenceFeature, SingleRequestFeature}, later); err != nil {
		t.Fatal(err)
	}
}
