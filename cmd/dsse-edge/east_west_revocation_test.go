package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/policy"

	"github.com/lantern-networks/dsse-core/decision"
)

func grantFor(device, dest, proto string, exp time.Time) decision.EastWestGrant {
	return decision.EastWestGrant{DeviceID: device, Destination: dest, Protocol: proto, ExpiresAt: exp}
}

func TestRevokeEastWestGrantsByDeviceScope(t *testing.T) {
	store := policy.NewStore(nil)
	exp := time.Now().Add(time.Hour)
	store.IssueEastWestGrant("t1", grantFor("dev1", "dc-01", "rdp", exp))
	store.IssueEastWestGrant("t1", grantFor("dev2", "dc-01", "rdp", exp))

	if n := store.RevokeEastWestGrants("t1", "device", "dev1"); n != 1 {
		t.Fatalf("expected 1 grant revoked for dev1; got %d", n)
	}
	got := store.EastWestGrantsFor("t1", time.Now())
	if len(got) != 1 || got[0].DeviceID != "dev2" {
		t.Fatalf("only dev2 grant should survive; got %+v", got)
	}
}
