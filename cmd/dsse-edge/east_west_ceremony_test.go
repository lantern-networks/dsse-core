package main

import (
	"testing"
	"time"

	eastwest "github.com/lantern-networks/dsse-core/eastwest"
	"github.com/lantern-networks/dsse-core/policy"

	"github.com/lantern-networks/dsse-core/model"
)

func ceremonyChallenge(challenges *eastwest.AuthChallengeStore, now time.Time, user string) eastwest.AuthChallenge {
	return challenges.Create(eastwest.BuildAuthChallenge(model.DecisionRequest{
		TenantID: "t1", UserID: user, DeviceID: "dev1", Destination: "dc-01", ServiceFamily: "rdp",
	}), now)
}

func TestCompleteEastWestCeremonyIssuesGrantOnIdentityMatch(t *testing.T) {
	store := policy.NewStore(nil)
	challenges := eastwest.NewAuthChallengeStore()
	now := time.Now()
	c := ceremonyChallenge(challenges, now, "u9") // subject falls back to user "u9"

	resp, err := eastwest.CompleteCeremony(store, challenges, c.ID, "u9", now)
	if err != nil {
		t.Fatalf("matching identity must issue a grant: %v", err)
	}
	if resp.Protocol != "rdp" || resp.Destination != "dc-01" {
		t.Fatalf("grant binding mismatch: %+v", resp)
	}
	if len(store.EastWestGrantsFor("t1", now)) != 1 {
		t.Fatal("ceremony should have issued exactly one active grant")
	}
	// The challenge is consumed.
	if len(challenges.ListPending("t1", now)) != 0 {
		t.Fatal("completed ceremony must consume the challenge")
	}
}

func TestCompleteEastWestCeremonyRejectsIdentityMismatch(t *testing.T) {
	store := policy.NewStore(nil)
	challenges := eastwest.NewAuthChallengeStore()
	now := time.Now()
	c := ceremonyChallenge(challenges, now, "u9")

	// A different user completing the browser ceremony must NOT release u9's held flow.
	if _, err := eastwest.CompleteCeremony(store, challenges, c.ID, "attacker", now); err == nil {
		t.Fatal("identity mismatch must be rejected")
	}
	if len(store.EastWestGrantsFor("t1", now)) != 0 {
		t.Fatal("rejected ceremony must not issue a grant")
	}
	// And the challenge must remain pending (not consumed by a failed attempt).
	if len(challenges.ListPending("t1", now)) != 1 {
		t.Fatal("rejected ceremony must leave the challenge pending")
	}
}
