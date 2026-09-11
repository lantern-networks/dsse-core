package main

import (
	"testing"
	"time"

	eastwest "github.com/lantern-networks/dsse-core/eastwest"
	"github.com/lantern-networks/dsse-core/policy"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

func TestEffectiveEastWestTTLCapsByRuleAndTenant(t *testing.T) {
	store := policy.NewStore(nil)
	store.SetEastWestRules("t1", []decision.EastWestRule{
		{ID: "r", Priority: 10, Destinations: []string{"dc-01"}, Protocols: []string{"rdp"}, Mode: "authenticate", MaxTTLSeconds: 3600},
	})
	store.SetEastWestMaxGrantTTL("t1", 7200)
	binding := decision.EastWestGrant{Destination: "dc-01", Protocol: "rdp"}

	// Requested 1 day -> capped to the smallest applicable (rule 3600s).
	if ttl := eastwest.EffectiveTTL(store, "t1", binding, 24*time.Hour); ttl != time.Hour {
		t.Fatalf("expected rule cap of 1h; got %v", ttl)
	}
	// Requested below all caps -> unchanged.
	if ttl := eastwest.EffectiveTTL(store, "t1", binding, 10*time.Minute); ttl != 10*time.Minute {
		t.Fatalf("expected 10m unchanged; got %v", ttl)
	}
	// A destination not governed by the sensitive rule -> only the tenant cap (7200s) applies.
	other := decision.EastWestGrant{Destination: "fileshare", Protocol: "smb"}
	if ttl := eastwest.EffectiveTTL(store, "t1", other, 24*time.Hour); ttl != 2*time.Hour {
		t.Fatalf("expected tenant cap of 2h; got %v", ttl)
	}
}

func TestIssueEastWestGrantDirectAppliesTenantCap(t *testing.T) {
	store := policy.NewStore(nil)
	store.SetEastWestMaxGrantTTL("t1", 60) // 60s ceiling
	now := time.Now()
	resp, err := eastwest.IssueGrantDirect(store, "t1", eastwest.AdminGrantIssueRequest{
		Destination: "dc-01", Protocol: "rdp", TTLSeconds: 86400, // asks for 1 day
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	exp, perr := time.Parse(time.RFC3339, resp.ExpiresAt)
	if perr != nil {
		t.Fatalf("parse expiry: %v", perr)
	}
	if exp.After(now.Add(2 * time.Minute)) {
		t.Fatalf("tenant cap (60s) not applied; expiry %v", resp.ExpiresAt)
	}
}

func TestTouchEastWestGrantBumpsLastUsed(t *testing.T) {
	store := policy.NewStore(nil)
	now := time.Now()
	store.IssueEastWestGrant("t1", decision.EastWestGrant{
		DeviceID: "dev1", Destination: "dc-01", Protocol: "rdp",
		ExpiresAt: now.Add(time.Hour), LastUsedAt: now.Add(-30 * time.Minute), IdleTTLSeconds: 60,
	})
	store.TouchEastWestGrant("t1", model.DecisionRequest{DeviceID: "dev1", Destination: "dc-01", ServiceFamily: "rdp"}, now)
	g := store.EastWestGrantsFor("t1", now)
	if len(g) != 1 || g[0].LastUsedAt.Before(now) {
		t.Fatalf("touch must bump LastUsedAt to now; got %+v", g)
	}
}
