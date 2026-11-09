package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentrollout"
)

// Found 2026-11-04 publishing a release to a new organization's Windows device: the control plane lists only
// organizations whose plan somebody wrote, so a new one was never in the set and its fleet was held for ever.
func TestAnOrganizationWithNoPlanInACompleteSetIsNotHeld(t *testing.T) {
	c := &agentRolloutCache{}
	c.setAll(map[string]agentrollout.AgentRolloutPlan{"tenant-a": {Frozen: true, Reason: "bad release"}}, "tenant-op", true)
	if p, known := c.planFor("tenant-new"); !known || p.Frozen {
		t.Fatalf("an organization with no plan in a complete set: known=%t frozen=%t; want known and not halted", known, p.Frozen)
	}
	if p, known := c.planFor("tenant-a"); !known || !p.Frozen {
		t.Fatal("an authored halt was lost")
	}
}

// An older control plane does not say its set is complete; then a missing organization is still "not told".
func TestAnIncompleteSetStillHoldsAnUnknownOrganization(t *testing.T) {
	c := &agentRolloutCache{}
	c.setAll(map[string]agentrollout.AgentRolloutPlan{"tenant-a": {}}, "tenant-op")
	if _, known := c.planFor("tenant-new"); known {
		t.Fatal("an organization missing from a set that did not claim to be complete was treated as known")
	}
	c.setAll(map[string]agentrollout.AgentRolloutPlan{"tenant-a": {}}, "tenant-op", true)
	c.setForTenant("tenant-op", agentrollout.AgentRolloutPlan{})
	if _, known := c.planFor("tenant-new"); known {
		t.Fatal("a single-plan answer kept the earlier set's completeness")
	}
}

// The pull reads the control plane's word for completeness off the wire.
func TestThePullReadsCompletenessFromTheControlPlane(t *testing.T) {
	for _, body := range []struct {
		json string
		want bool
	}{
		{`{"tenants":{"tenant-a":{}},"complete":true}`, true},
		{`{"tenants":{"tenant-a":{}}}`, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body.json))
		}))
		plans, served, complete, err := agentRolloutSource{url: srv.URL, client: srv.Client()}.fetchAllComplete(context.Background())
		srv.Close()
		if err != nil || !served || len(plans) != 1 || complete != body.want {
			t.Fatalf("%s: served=%t complete=%t err=%v", body.json, served, complete, err)
		}
	}
}

// And the control plane says so only when it answered for the whole deployment.
func TestTheControlPlaneSaysItsSetIsCompleteOnlyForTheDeployment(t *testing.T) {
	b, err := os.ReadFile("admin_agent_quality.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"complete": forTheDeployment,`) {
		t.Fatal("GET /admin/agent-rollouts does not say whether its set is every plan")
	}
}
