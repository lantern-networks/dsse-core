package grantstore

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func seedCapacityFences(s *Store, now time.Time) {
	for i := 0; i < MaxReauthenticationFencesPerTenant; i++ {
		g := rollingGrant(fmt.Sprint(i), now)
		g.Scope = fmt.Sprintf("app:%d", i)
		g.IssuedAt = now.Format(time.RFC3339)
		g.ExpiresAt = now.Add(time.Minute).Format(time.RFC3339)
		g.Revoked = true
		g.ReauthenticateAfter = now.Format(time.RFC3339Nano)
		s.grants[g.GrantID] = g
	}
	s.rebuildReauthenticationIndexLocked()
}

func TestConsolidatedFenceSurvivesFailedCommitRefreshRetryAndDistribution(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := NewStore()
	seedCapacityFences(s, now)
	p := &grantSharedFixture{}
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	g := rollingGrant("target", now)
	g.Scope = "new:22"
	if _, err := s.Mint(g, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	p.fail = true
	revoked, found, err := s.RequireReauthenticationForTenantContext(context.Background(), g.TenantID, g.GrantID, now.Add(time.Second))
	if !found || !errors.Is(err, ErrPersistence) || !revoked.Revoked {
		t.Fatal("failed commit did not retain denial", found, err)
	}
	if err := s.RefreshShared(); err != nil {
		t.Fatal(err)
	}
	if s.ReauthenticationScope(revoked) != "tenant" {
		t.Fatal("refresh dropped uncommitted wider denial")
	}
	p.fail = false
	if _, found, err := s.RequireReauthenticationForTenantContext(context.Background(), g.TenantID, g.GrantID, now.Add(2*time.Second)); !found || err != nil {
		t.Fatal("retry failed", err)
	}
	edge := NewStore()
	otherUser := rollingGrant("other-user", now)
	otherUser.UserID = "different-person"
	otherUser.DeviceID = "different-device"
	otherUser.Scope = "different:443"
	otherUser, err = edge.Mint(otherUser, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListAllChecked()
	if err != nil {
		t.Fatal(err)
	}
	ordinary, protected := SplitTransport(rows)
	if len(ordinary) != 0 || len(protected) == 0 {
		t.Fatal("revocation evidence leaked to legacy readers")
	}
	if _, _, err := edge.MergeAuthorityEvidence(rows, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if edge.AuthorizationFresh(otherUser, otherUser.Scope) {
		t.Fatal("distributed wide boundary did not cover another identity/device/resource")
	}
	if _, _, err := edge.MergeAuthorityEvidence([]Grant{otherUser}, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if edge.AuthorizationFresh(otherUser, otherUser.Scope) {
		t.Fatal("stale snapshot removed wide boundary")
	}
	if _, err := edge.RemoveTenantChecked(g.TenantID); err != nil {
		t.Fatal(err)
	}
	if !edge.AuthorizationFresh(otherUser, otherUser.Scope) {
		t.Fatal("tenant erasure retained stale index")
	}
}

func TestReauthenticationIndexPreservesWildcardMatching(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rows := map[string]Grant{}
	for i := 0; i < 512; i++ {
		g := rollingGrant(fmt.Sprint(i), now)
		g.Revoked = true
		g.ReauthenticateAfter = now.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		if i%2 == 0 {
			g.UserID = ""
		}
		if i%3 == 0 {
			g.DeviceID = ""
		}
		if i%5 == 0 {
			g.Scope = ""
		}
		if i%7 == 0 {
			g.TenantID = "other"
		}
		if i%11 == 0 {
			g.Issuer = ""
		}
		rows[g.GrantID] = g
	}
	index := newReauthenticationReadIndex(rows)
	for _, tenant := range []string{"tenant", "other", "absent"} {
		for _, user := range []string{"", "sub", "another"} {
			for _, scope := range []string{"", "host:22", "other:443"} {
				subject := rollingGrant("subject", now)
				subject.TenantID = tenant
				subject.UserID = user
				var want time.Time
				for _, g := range rows {
					if reauthenticationMatches(g, subject, scope) {
						at, _ := time.Parse(time.RFC3339Nano, g.ReauthenticateAfter)
						if at.After(want) {
							want = at
						}
					}
				}
				if got := index.after(subject, scope); !got.Equal(want) {
					t.Fatal("indexed wildcard changed denial", tenant, user, scope, got, want)
				}
			}
		}
	}
}

func BenchmarkReauthenticationIndexedManyTenants(b *testing.B) {
	index := make(reauthenticationReadIndex)
	now := time.Now().UTC()
	for tenant := 0; tenant < 100; tenant++ {
		tid := fmt.Sprint(tenant)
		index[tid] = make(map[string]map[string]reauthenticationFenceIndex)
		for user := 0; user < 4096; user++ {
			uid := fmt.Sprint(user)
			key := reauthenticationSelector{tenant: tid, user: uid, scope: "app:22"}
			index[tid][uid] = map[string]reauthenticationFenceIndex{"app:22": {key: {id: uid, at: now}}}
		}
	}
	subject := Grant{TenantID: "50", UserID: "2048"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if index.after(subject, "app:22").IsZero() {
			b.Fatal("boundary missing")
		}
	}
}

func BenchmarkReauthenticationIndexedManyScopes(b *testing.B) {
	index := make(reauthenticationReadIndex)
	now := time.Now().UTC()
	for tenant := 0; tenant < 100; tenant++ {
		tid := fmt.Sprint(tenant)
		index[tid] = map[string]map[string]reauthenticationFenceIndex{"user": {}}
		for scope := 0; scope < 4096; scope++ {
			sid := fmt.Sprint(scope)
			key := reauthenticationSelector{tenant: tid, user: "user", scope: sid}
			index[tid]["user"][sid] = reauthenticationFenceIndex{key: {id: sid, at: now}}
		}
	}
	subject := Grant{TenantID: "50", UserID: "user"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if index.after(subject, "2048").IsZero() {
			b.Fatal("boundary missing")
		}
	}
}

func TestCapacityBoundaryRemainsProtectedThroughRollingStorage(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := NewStore()
	seedCapacityFences(s, now)
	p := RollingPersister{&rollingMemory{}}
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	g := Grant{GrantID: "new", TenantID: "tenant", Scope: "new"}
	if _, err := s.Mint(g, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.RequireReauthenticationForTenantContext(context.Background(), g.TenantID, g.GrantID, now); err != nil || !found {
		t.Fatal(err)
	}
	if _, err := s.PruneExpired(context.Background(), now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	restored := NewStore()
	if err := restored.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	after, err := restored.ReauthenticationAfterChecked(Grant{TenantID: "tenant", UserID: "other-user"}, "other-resource")
	if err != nil || after.IsZero() {
		t.Fatal("rolling storage lost consolidated boundary", err)
	}
}
