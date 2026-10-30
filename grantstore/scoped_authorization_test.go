package grantstore

import (
	old "github.com/lantern-networks/dsse-core/grantstore/testdata/releasedv031"
	"testing"
	"time"
)

func TestScopedGrantCannotReachReleasedReader(t *testing.T) {
	current, released, _ := rollingStores(t)
	now := time.Now().UTC().Truncate(time.Second)
	g := rollingGrant("scoped", now)
	g.Scope = "fileserver:445"
	g.RequiredFeatures = []string{FeatureScopedAuthorization}
	if _, err := current.Mint(g, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if released.Valid(g.GrantID, now) || old.GateAccepts(released, g.TenantID, g.DeviceID, "") {
		t.Fatal("released gate accepted a new destination-scoped grant")
	}
	if got, ok := current.Get(g.GrantID); !ok || !got.Supported() {
		t.Fatal("current reader rejected scoped grant")
	}
}

func TestRemovedIdentityEvidenceCannotBeAuthorized(t *testing.T) {
	g := Grant{RequiredFeatures: []string{"cross-scope-identity-evidence-v1"}}
	if g.Supported() {
		t.Fatal("removed cross-scope feature is still supported")
	}
}
