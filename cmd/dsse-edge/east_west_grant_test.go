package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	eastwest "github.com/lantern-networks/dsse-core/eastwest"
	"github.com/lantern-networks/dsse-core/policy"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestRuntimeGrantRouteCannotCompleteChallengeWithoutBrowserIdentity(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, LabMode: boolPtr(true)})
	// The held endpoint is given the challenge ID in its 401 response. Sending
	// that ID to this runtime route must never stand in for an OIDC callback.
	request := httptest.NewRequest(http.MethodPost, "/east-west/grant", strings.NewReader(`{"challenge_id":"ewc_0123456789abcdef0123456789abcdef"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("bare challenge ID received status %d, want refusal", recorder.Code)
	}
}

func TestIssueEastWestGrantFromChallengeReleasesAndCompletes(t *testing.T) {
	store := policy.NewStore(nil)
	challenges := eastwest.NewAuthChallengeStore()
	now := time.Now()
	const tenant = "tenant_test"

	challenge := challenges.Create(eastwest.BuildAuthChallenge(model.DecisionRequest{
		TenantID: tenant, UserID: "u9", DeviceID: "dev1", Destination: "dc-01", ServiceFamily: "rdp",
	}), now)

	resp, err := eastwest.CompleteCeremony(store, challenges, challenge.ID, tenant, "u9", now)
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
	if _, err := eastwest.CompleteCeremony(store, challenges, challenge.ID, tenant, "u9", now); err == nil {
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
