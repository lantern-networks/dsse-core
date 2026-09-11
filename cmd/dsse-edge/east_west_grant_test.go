package main

import (
	"testing"
	"time"

	eastwest "github.com/lantern-networks/dsse-core/eastwest"
	"github.com/lantern-networks/dsse-core/policy"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

func TestIssueEastWestGrantFromChallengeReleasesAndCompletes(t *testing.T) {
	store := policy.NewStore(nil)
	challenges := eastwest.NewAuthChallengeStore()
	now := time.Now()
	const tenant = "tenant_test"

	challenge := challenges.Create(eastwest.BuildAuthChallenge(model.DecisionRequest{
		TenantID: tenant, UserID: "u9", DeviceID: "dev1", Destination: "dc-01", ServiceFamily: "rdp",
	}), now)

	resp, err := eastwest.IssueGrantFromChallenge(store, challenges, challenge.ID, now)
	if err != nil {
		t.Fatalf("issue grant: %v", err)
	}
	if resp.Destination != "dc-01" || resp.Protocol != "rdp" || resp.SubjectUserID != "u9" || resp.DeviceID != "dev1" {
		t.Fatalf("grant binding mismatch: %+v", resp)
	}

	// The grant is now active in the store for the tenant, bound to the challenge.
	grants := store.EastWestGrantsFor(tenant, now)
	if len(grants) != 1 || grants[0].Destination != "dc-01" || grants[0].Protocol != "rdp" {
		t.Fatalf("expected 1 active grant bound to dc-01/rdp; got %+v", grants)
	}
	// Default TTL ~1 day.
	if !grants[0].ExpiresAt.After(now.Add(23*time.Hour)) || grants[0].ExpiresAt.After(now.Add(25*time.Hour)) {
		t.Fatalf("grant TTL should be ~1 day; got expiry %v", grants[0].ExpiresAt)
	}

	// The challenge is consumed (completed) -> issuing again fails, and it is no longer pending.
	if _, err := eastwest.IssueGrantFromChallenge(store, challenges, challenge.ID, now); err == nil {
		t.Fatal("re-issuing against a completed challenge must fail")
	}
	if got := challenges.ListPending(tenant, now); len(got) != 0 {
		t.Fatalf("completed challenge must not be pending; got %v", got)
	}
}

func TestEastWestGrantsForExcludesExpired(t *testing.T) {
	store := policy.NewStore(nil)
	now := time.Now()
	store.IssueEastWestGrant("t1", decision.EastWestGrant{Destination: "dc-01", Protocol: "rdp", ExpiresAt: now.Add(time.Hour)})
	store.IssueEastWestGrant("t1", decision.EastWestGrant{Destination: "dc-02", Protocol: "ssh", ExpiresAt: now.Add(-time.Minute)}) // expired
	got := store.EastWestGrantsFor("t1", now)
	if len(got) != 1 || got[0].Destination != "dc-01" {
		t.Fatalf("expected only the non-expired grant; got %+v", got)
	}
}
