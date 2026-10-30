package grantstore

import (
	"context"
	"testing"
	"time"
)

func TestRollingRetentionNeverDeletesLegacyRowsDuringCoexistence(t *testing.T) {
	n, o, m := rollingStores(t)
	now := time.Now().UTC().Truncate(time.Second)
	regular := rollingGrant("ordinary", now)
	if _, e := n.Mint(regular, time.Minute, now); e != nil {
		t.Fatal(e)
	}
	g := rollingGrant("single", now)
	g.AuthenticationRequestID = "req"
	g.ReauthenticationStartedAt = now.Format(time.RFC3339)
	g, e := n.Mint(g, time.Minute, now)
	if e != nil {
		t.Fatal(e)
	}
	if yes, e := n.ConsumeAuthenticationRequest(context.Background(), g, now); e != nil || !yes {
		t.Fatal(e)
	}
	if count, e := n.PruneExpired(context.Background(), now.Add(time.Minute+ExpiredRetention-time.Second)); e != nil || count != 0 {
		t.Fatal("early pruning", count, e)
	}
	a, b, _ := m.LoadGrantPair(context.Background())
	m.fail = true
	if _, e := n.PruneExpired(context.Background(), now.Add(time.Hour)); e == nil {
		t.Fatal("save failure hidden")
	}
	x, y, _ := m.LoadGrantPair(context.Background())
	if string(a) != string(x) || string(b) != string(y) {
		t.Fatal("failed prune committed")
	}
	m.fail = false
	if count, e := n.PruneExpired(context.Background(), now.Add(time.Hour)); e != nil || count != 1 {
		t.Fatal(count, e)
	}
	if _, ok := n.Get("single"); ok {
		t.Fatal("expired request tombstone retained")
	}
	if _, ok := o.Get("ordinary"); !ok {
		t.Fatal("pruned legacy row before fleet migration completed")
	}
}
func TestLocalRetentionDeletesExpiredRowsButKeepsActive(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC()
	for id, ttl := range map[string]time.Duration{"old": time.Minute, "live": time.Hour} {
		if _, e := s.Mint(Grant{GrantID: id, TenantID: "t"}, ttl, now); e != nil {
			t.Fatal(e)
		}
	}
	if n, e := s.PruneExpired(context.Background(), now.Add(20*time.Minute)); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	if s.RetentionStats().Rows != 1 || s.RetentionStats().SnapshotBytes == 0 {
		t.Fatal("invalid capacity stats")
	}
	if !s.Valid("live", now.Add(20*time.Minute)) {
		t.Fatal("pruned active grant")
	}
}
