package grantstore

import (
	old "github.com/lantern-networks/dsse-core/grantstore/testdata/releasedv031"
	"strings"
	"testing"
	"time"
)

func TestDeviceUserGrantCannotReachReleasedReader(t *testing.T) {
	current, released, pair := rollingStores(t)
	now := time.Now().UTC().Truncate(time.Second)
	g := rollingGrant("owner", now)
	g.OSPrincipal = "windows:S-1-5-21-100-200-300-1001"
	g.OSSession = strings.Repeat("a", 64)
	minted, e := current.Mint(g, time.Hour, now)
	if e != nil {
		t.Fatal(e)
	}
	if !minted.RequiresModernReader() || len(minted.RequiredFeatures) != 1 || minted.RequiredFeatures[0] != FeatureDeviceUser {
		t.Fatal("missing enforced capability")
	}
	if released.Valid(g.GrantID, now) || old.GateAccepts(released, "tenant", "device", "") {
		t.Fatal("released gate authorized owner-bound grant")
	}
	if _, e = released.Mint(old.Grant{GrantID: "unrelated", TenantID: "other"}, time.Minute, now); e != nil {
		t.Fatal(e)
	}
	reloaded := NewStore()
	if e = reloaded.SetPersister(RollingPersister{pair}); e != nil {
		t.Fatal(e)
	}
	got, ok := reloaded.Get(g.GrantID)
	if !ok || got.OSPrincipal != g.OSPrincipal || got.OSSession != g.OSSession || !reloaded.Valid(g.GrantID, now) {
		t.Fatal("released writer lost owner evidence")
	}
	changed := got
	changed.OSSession = strings.Repeat("b", 64)
	if _, _, e = reloaded.MergeChecked([]Grant{changed}, now); e != ErrConflict {
		t.Fatal("owner binding mutated", e)
	}
	for _, bad := range []Grant{{GrantID: "a", TenantID: "tenant", RequiredFeatures: []string{FeatureDeviceUser}}, {GrantID: "b", TenantID: "tenant", OSPrincipal: g.OSPrincipal, OSSession: g.OSSession}} {
		if _, e = current.Mint(bad, time.Minute, now); e == nil {
			t.Fatal("incomplete owner grant minted")
		}
	}
}
