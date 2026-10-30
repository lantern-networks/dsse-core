package grantstore

import (
	"context"
	"encoding/json"
	"errors"
	old "github.com/lantern-networks/dsse-core/grantstore/testdata/releasedv031"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdministrativeRevocationRejectsReplacementSSOAndSurvivesRestart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := NewStore()
	path := filepath.Join(t.TempDir(), "grants.json")
	if e := s.SetStatePath(path); e != nil {
		t.Fatal(e)
	}
	old := rollingGrant("old", now)
	old.AuthTime = now.Add(-time.Hour).Format(time.RFC3339)
	for _, id := range []string{"old", "sibling"} {
		g := old
		g.GrantID = id
		if _, e := s.Mint(g, time.Hour, now); e != nil {
			t.Fatal(e)
		}
	}
	cutoff := now.Add(500 * time.Millisecond)
	revoked, ok, e := s.RequireReauthenticationForTenantContext(context.Background(), "tenant", "old", cutoff)
	if e != nil || !ok || revoked.ReauthenticateAfter == "" {
		t.Fatalf("revoke: %+v %v", revoked, e)
	}
	retry, _, e := s.RequireReauthenticationForTenantContext(context.Background(), "tenant", "old", now.Add(time.Second))
	if e != nil || retry.ReauthenticateAfter != revoked.ReauthenticateAfter {
		t.Fatal("retry renewed revocation")
	}
	if s.Valid("sibling", now.Add(time.Second)) {
		t.Fatal("other ID reused old authentication")
	}
	for _, auth := range []string{"", old.AuthTime, now.Format(time.RFC3339)} {
		g := old
		g.GrantID = "replacement"
		g.AuthTime = auth
		if _, e = s.Mint(g, time.Hour, now.Add(2*time.Second)); !errors.Is(e, ErrReauthenticationRequired) {
			t.Fatalf("stale SSO accepted: %v", e)
		}
	}
	fresh := old
	fresh.GrantID = "fresh"
	fresh.AuthTime = now.Add(time.Second).Format(time.RFC3339)
	if _, e = s.Mint(fresh, time.Hour, now.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	reloaded := NewStore()
	if e = reloaded.SetStatePath(path); e != nil {
		t.Fatal(e)
	}
	if reloaded.Valid("old", now.Add(3*time.Second)) || reloaded.Valid("sibling", now.Add(3*time.Second)) || !reloaded.Valid("fresh", now.Add(3*time.Second)) {
		t.Fatal("restart changed revocation freshness")
	}
}

func TestAdministrativeRevocationScopeAndLogoutCannotBypass(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := NewStore()
	old := rollingGrant("old", now)
	old.OSPrincipal = "windows:S-1-5-21-100-200-300-1001"
	old.OSSession = strings.Repeat("a", 64)
	if _, e := s.Mint(old, time.Minute, now); e != nil {
		t.Fatal(e)
	}
	if _, _, e := s.RequireReauthenticationForTenantContext(context.Background(), "tenant", "old", now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		name string
		edit func(*Grant)
		want bool
	}{
		{"same-owner", func(g *Grant) {}, false},
		{"wide-scope", func(g *Grant) { g.Scope = "" }, false},
		{"new-session", func(g *Grant) { g.OSSession = strings.Repeat("b", 64) }, false},
		{"provider-config-edit", func(g *Grant) {
			g.ProviderConfigSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		}, false},
		{"other-tenant", func(g *Grant) { g.TenantID = "elsewhere" }, true},
		{"other-user", func(g *Grant) { g.UserID = "other" }, true},
		{"other-device", func(g *Grant) { g.DeviceID = "other" }, true},
		{"other-provider", func(g *Grant) { g.IdPID = "other" }, true},
		{"other-resource", func(g *Grant) { g.Scope = "other:22" }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := old
			g.GrantID = test.name
			test.edit(&g)
			_, e := s.Mint(g, time.Minute, now.Add(2*time.Second))
			if (e == nil) != test.want {
				t.Fatalf("accepted=%v want=%v: %v", e == nil, test.want, e)
			}
		})
	}
	// Expiry of the revoked original does not forget the revocation boundary.
	g := old
	g.GrantID = "after-expiry"
	if _, e := s.Mint(g, time.Minute, now.Add(time.Hour)); !errors.Is(e, ErrReauthenticationRequired) {
		t.Fatal("expired original erased boundary")
	}
}

func TestAdministrativeRevocationSharedSaveFailureAndStaleReport(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	p := &grantSharedFixture{}
	a, b := NewStore(), NewStore()
	for _, s := range []*Store{a, b} {
		if e := s.SetPersister(p); e != nil {
			t.Fatal(e)
		}
	}
	old := rollingGrant("old", now)
	if _, e := a.Mint(old, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	if _, e := b.ListChecked("tenant"); e != nil {
		t.Fatal(e)
	}
	p.fail = true
	denied, ok, e := a.RequireReauthenticationForTenantContext(context.Background(), "tenant", "old", now.Add(time.Second))
	if !ok || !errors.Is(e, ErrPersistence) || denied.ReauthenticateAfter == "" {
		t.Fatalf("failed revoke lost denial: %v", e)
	}
	replacement := old
	replacement.GrantID = "stale-replacement"
	if _, e := a.Mint(replacement, time.Hour, now.Add(2*time.Second)); !errors.Is(e, ErrReauthenticationRequired) {
		t.Fatal("pending fence admitted old SSO", e)
	}
	p.fail = false
	if _, _, e := a.RequireReauthenticationForTenantContext(context.Background(), "tenant", "old", now.Add(3*time.Second)); e != nil {
		t.Fatal(e)
	}
	stale := old
	stale.IssuedAt = now.Format(time.RFC3339)
	stale.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339)
	if _, _, e := b.MergeChecked([]Grant{stale}, now.Add(4*time.Second)); e != nil {
		t.Fatal(e)
	}
	rows, e := b.ListChecked("tenant")
	if e != nil || len(rows) != 1 || rows[0].ReauthenticateAfter != denied.ReauthenticateAfter {
		t.Fatal("stale report removed or renewed boundary")
	}
	replacement.GrantID = "peer-replacement"
	if _, e := b.Mint(replacement, time.Hour, now.Add(5*time.Second)); !errors.Is(e, ErrReauthenticationRequired) {
		t.Fatal("shared authority bypass", e)
	}
	p.loadFail = true
	if _, e := b.ReauthenticationAfterChecked(old, old.Scope); e == nil {
		t.Fatal("read failure treated as no revocation")
	}
}

func TestAdministrativeRevocationMalformedBoundaryFailsClosedAndLegacyCannotUseIt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	n, o, _ := rollingStores(t)
	g := rollingGrant("old", now)
	if _, e := n.Mint(g, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	if _, _, e := n.RequireReauthenticationForTenantContext(context.Background(), "tenant", "old", now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if o.Valid("old", now.Add(2*time.Second)) {
		t.Fatal("released reader treated revoked evidence as allowed")
	}
	fresh := g
	fresh.GrantID = "fresh"
	fresh.AuthTime = now.Add(2 * time.Second).Format(time.RFC3339)
	if _, e := n.Mint(fresh, time.Hour, now.Add(3*time.Second)); e != nil {
		t.Fatal(e)
	}
	if o.Valid("fresh", now.Add(4*time.Second)) {
		t.Fatal("released reader used new-semantics evidence")
	}
	// Preserve all sidecar rows while an old writer updates the legacy partition.
	if _, e := o.Mint(old.Grant{GrantID: "unrelated", TenantID: "other"}, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	rows := n.ListAll()
	rows[0].ReauthenticateAfter = "malformed"
	rows[0].Revoked = true
	raw, _ := json.Marshal(map[string]any{"schema_version": 3, "grants": map[string]Grant{rows[0].GrantID: rows[0]}})
	if _, e := decodeShared(raw); e == nil {
		t.Fatal("malformed fence was silently discarded")
	}
}

func TestSingleRequestConsumptionAndExpiryDoNotCreateAdministrativeBoundary(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := NewStore()
	one, e := s.Mint(requestGrant(now), time.Minute, now)
	if e != nil {
		t.Fatal(e)
	}
	if ok, e := s.ConsumeAuthenticationRequest(context.Background(), one, now); e != nil || !ok {
		t.Fatal(e)
	}
	after, e := s.ReauthenticationAfterChecked(one, one.Scope)
	if e != nil || !after.IsZero() {
		t.Fatal("using one request created an administrative revocation")
	}
	replacement := requestGrant(now)
	replacement.GrantID = "next"
	replacement.AuthenticationRequestID = "new-request"
	if _, e := s.Mint(replacement, time.Minute, now); e != nil {
		t.Fatal("consumption prevented a separate valid request", e)
	}
}

func TestRevocationBoundaryRejectsEqualOrFutureAuthTimeDespiteClockSkew(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := NewStore()
	old := rollingGrant("clock-ahead", now)
	old.AuthTime = now.Add(-time.Hour).Format(time.RFC3339)
	if _, e := s.Mint(old, time.Hour, now.Add(10*time.Second)); e != nil {
		t.Fatal(e)
	}
	// A skewed mint timestamp must not prevent a real administrative denial.
	if g, found, e := s.RequireReauthenticationForTenantContext(context.Background(), "tenant", "clock-ahead", now); e != nil || !found || !g.Revoked {
		t.Fatal("clock skew prevented revocation", e)
	}
	for _, auth := range []time.Time{now, now.Add(10 * time.Second)} {
		g := old
		g.GrantID = "replacement"
		g.AuthTime = auth.Format(time.RFC3339)
		if _, e := s.Mint(g, time.Hour, now); !errors.Is(e, ErrReauthenticationRequired) {
			t.Fatal("equal or future time bypassed revocation", e)
		}
	}
}
