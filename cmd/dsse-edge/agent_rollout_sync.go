package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/agentrollout"
)

// agent_rollout_sync.go — CP→Edge sync for the halt and the wave schedule.
//
// ★ WHY IT EXISTS (2026-08-11, from a review). `PUT /admin/agent-rollout` validated a plan, stored it in an
// in-process map, wrote an audit entry and answered 200 — and devices took their plan from a FILE on each Edge
// that nothing ever wrote. An operator could halt a bad release, watch it succeed, and every endpoint would
// carry on installing. The freeze is the only mechanism that stops a release already in the fleet's hands, so
// the one control everything else leans on was the one that reached nobody.
//
// This is the same shape steer exclusions already use, and deliberately: the CONTROL PLANE owns the durable
// answer, the enforcing Edge PULLS it into an in-memory cache, and a fetch failure keeps the last good copy
// rather than reverting to a default. An Edge restart re-populates from the CP, which is what makes a halt
// survive one.
//
// ★ AND THE ASYMMETRY THAT MAKES IT SAFE: until the first pull succeeds, an Edge configured to pull serves
// FROZEN. "I have not been told whether the fleet is halted" and "the fleet is not halted" must not render the
// same, and of the two ways to be wrong, holding a release for one poll interval is the recoverable one.

// agentRolloutCache is what the plan route reads on an Edge that pulls from a control plane.
//
// restart-durability: cp_durable — the control plane owns every organization's plan and this is a copy of it,
// re-pulled on the first tick after start-up. Losing it is not losing the plan: an Edge with nothing in it
// serves FROZEN, so the failure direction is a fleet held until it has been told, never a fleet released by a
// restart. Persisting it would add a second answer to "is this fleet halted", which is the defect the plan
// route's own history is made of.
//
// populated-by: assertion — the pull loop below fills it on its first tick and every minute after, from
// GET /admin/agent-rollouts (every organization this deployment holds a plan for) with the single-plan route
// as the fallback for an older control plane. Nothing else writes it: a plan that arrived any other way would
// be a second authority on whether a fleet is halted.
type agentRolloutCache struct {
	mu      sync.RWMutex
	plan    agentrollout.AgentRolloutPlan
	fetched bool
	lastErr string
	// plans is EVERY organization's plan this Edge serves, keyed by organization.
	//
	// ★★★ ONE PLAN WAS NOT ENOUGH FOR A NODE THAT SERVES SEVERAL (2026-08-28). An enforcing Edge pulled a
	// single plan, for its own enforcement tenant, and the honest thing was done with it: a device of any other
	// organization was HELD, because "I have not been told whether that fleet is halted" must not read like
	// "it is not halted". Safe, and it means every customer's fleet on a pulling Edge is held for ever — they
	// are never told anything, so they never move.
	//
	// So the Edge asks for the set. An organization in it is answered from its own plan; one that is not is
	// held exactly as before, which keeps the property this cache was built on.
	plans map[string]agentrollout.AgentRolloutPlan
	// tenantID is the tenant this cache's plan was pulled FOR. An enforcing Edge pulls one plan, for its own
	// enforcement tenant, and may serve devices belonging to another tenant when several Tenant CAs are
	// registered — a form this product supports.
	//
	// ★ WITHOUT IT THE HALT WAS ANSWERED FOR THE WRONG TENANT (2026-08-13, thirty-first review #6). The route
	// stamps the plan it signs with the DEVICE's tenant, from its client certificate, while the content came
	// from whatever this Edge pulled: a tenant-B device received a plan labelled tenant B carrying tenant A's
	// freeze. The previous round fixed this for a combined control plane and left the pulling topology as it
	// was — the same defect, one door along.
	tenantID string
}

// TenantID is the tenant this cache's plan was pulled for, or "" when it was never told.
func (c *agentRolloutCache) TenantID() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tenantID
}

// Get reports the cached plan and whether anything has ever been fetched.
func (c *agentRolloutCache) Get() (agentrollout.AgentRolloutPlan, bool, string) {
	if c == nil {
		return agentrollout.AgentRolloutPlan{}, false, ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.plan, c.fetched, c.lastErr
}

func (c *agentRolloutCache) setForTenant(tenantID string, p agentrollout.AgentRolloutPlan) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tenantID = strings.TrimSpace(tenantID)
	c.plan, c.fetched, c.lastErr = p, true, ""
	if c.plans == nil {
		c.plans = map[string]agentrollout.AgentRolloutPlan{}
	}
	if key := strings.ToLower(strings.TrimSpace(tenantID)); key != "" {
		c.plans[key] = p
	}
}

// setAll replaces what this Edge knows about every organization it serves.
func (c *agentRolloutCache) setAll(plans map[string]agentrollout.AgentRolloutPlan, own string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := make(map[string]agentrollout.AgentRolloutPlan, len(plans))
	for k, v := range plans {
		if key := strings.ToLower(strings.TrimSpace(k)); key != "" {
			next[key] = v
		}
	}
	c.plans, c.fetched, c.lastErr = next, true, ""
	c.tenantID = strings.TrimSpace(own)
	if p, ok := next[strings.ToLower(strings.TrimSpace(own))]; ok {
		c.plan = p
	}
}

// planFor answers one organization's plan, and whether this Edge has been told anything about it. The second
// value is what keeps "not told" from rendering as "not halted".
func (c *agentRolloutCache) planFor(tenantID string) (agentrollout.AgentRolloutPlan, bool) {
	if c == nil {
		return agentrollout.AgentRolloutPlan{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.fetched {
		return agentrollout.AgentRolloutPlan{}, false
	}
	key := strings.ToLower(strings.TrimSpace(tenantID))
	if key == "" {
		return c.plan, true
	}
	if p, ok := c.plans[key]; ok {
		return p, true
	}
	// The single-plan answer an older control plane gives: it is this Edge's own organization's and nobody
	// else's, which is exactly what the caller must not spread around.
	if strings.EqualFold(key, strings.TrimSpace(c.tenantID)) {
		return c.plan, true
	}
	return agentrollout.AgentRolloutPlan{}, false
}

func (c *agentRolloutCache) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastErr = err.Error()
}

// agentRolloutSource pulls the tenant's rollout plan from the control plane.
type agentRolloutSource struct {
	url   string
	token string
	// tenantID is the enforcement tenant of THIS edge. The control plane's answer names the tenant it is for,
	// and a mismatch is not applied.
	//
	// ★ A WRONG TOKEN OR A WRONG URL MUST NOT HALT (OR RELEASE) SOMEBODY ELSE'S FLEET (2026-08-11, third
	// review). The response carries tenant_id and this decoded only the plan, so an edge pointed at the wrong
	// control plane — or holding a token scoped to another tenant — would apply that tenant's freeze to its
	// own devices, or worse, its unfreeze.
	tenantID string
	interval time.Duration
	client   *http.Client
}

// fetchAll asks for EVERY organization's plan. An older control plane has no such route and answers 404, which
// is not an error: the caller falls back to the singular fetch and this Edge behaves exactly as it did.
func (s agentRolloutSource) fetchAll(ctx context.Context) (map[string]agentrollout.AgentRolloutPlan, bool, error) {
	url := strings.TrimRight(s.url, "/") + "/admin/agent-rollouts"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("control plane answered HTTP %d", resp.StatusCode)
	}
	var body struct {
		TenantID string                                   `json:"tenant_id"`
		Tenants  map[string]agentrollout.AgentRolloutPlan `json:"tenants"`
	}
	if derr := json.NewDecoder(io.LimitReader(resp.Body, maxPublishedSetBytes)).Decode(&body); derr != nil {
		return nil, false, fmt.Errorf("decode the rollout plans: %w", derr)
	}
	return body.Tenants, true, nil
}

func (s agentRolloutSource) fetch(ctx context.Context) (agentrollout.AgentRolloutPlan, error) {
	url := strings.TrimRight(s.url, "/") + "/admin/agent-rollout"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return agentrollout.AgentRolloutPlan{}, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return agentrollout.AgentRolloutPlan{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return agentrollout.AgentRolloutPlan{}, fmt.Errorf("control plane answered HTTP %d", resp.StatusCode)
	}
	var body struct {
		TenantID string                        `json:"tenant_id"`
		Plan     agentrollout.AgentRolloutPlan `json:"plan"`
	}
	if derr := json.NewDecoder(resp.Body).Decode(&body); derr != nil {
		return agentrollout.AgentRolloutPlan{}, fmt.Errorf("decode the rollout plan: %w", derr)
	}
	if want := strings.TrimSpace(s.tenantID); want != "" && !strings.EqualFold(strings.TrimSpace(body.TenantID), want) {
		return agentrollout.AgentRolloutPlan{}, fmt.Errorf("the control plane answered for tenant %q and this edge "+
			"enforces %q — refusing to apply another tenant's halt (or its release) to these devices",
			body.TenantID, want)
	}
	return body.Plan, nil
}

// run polls until the context ends. The first pull is immediate: an Edge that has just restarted is serving
// FROZEN until it succeeds, so waiting a full interval would halt the fleet for no reason.
func (s agentRolloutSource) run(ctx context.Context, cache *agentRolloutCache) {
	// ★ THE FIRST SUCCESS IS LOGGED, and so is the start (2026-08-11). Logging only failures makes "pulling
	// fine, nothing to say" and "this goroutine never ran" identical in the log — and an Edge whose poller never
	// started serves FROZEN forever while looking healthy. That pair is the whole family of defects this session
	// has been removing; it must not be reintroduced by a logging choice.
	log.Printf("agent-rollout sync: pulling the halt from %s every %s (this edge serves FROZEN until the first "+
		"successful pull)", s.url, s.interval)
	first := true
	pull := func() {
		// ★ THE WHOLE SET FIRST. This Edge serves every organization on the deployment, and being told about
		// one of them means holding all the others for ever. An older control plane has no such route and
		// answers 404, which is not a failure — the singular pull below is then exactly what it always was.
		if all, served, aerr := s.fetchAll(ctx); aerr == nil && served {
			prevAll, hadAll, _ := cache.Get()
			cache.setAll(all, s.tenantID)
			own := all[strings.ToLower(strings.TrimSpace(s.tenantID))]
			switch {
			case first:
				first = false
				log.Printf("agent-rollout sync: first pull succeeded — %d organization(s), this edge's own is "+
					"frozen=%t reason=%q", len(all), own.Frozen, own.Reason)
			case !hadAll || prevAll.Frozen != own.Frozen || prevAll.Reason != own.Reason:
				log.Printf("agent-rollout sync: the halt changed — frozen=%t reason=%q (%d organization(s) known)",
					own.Frozen, own.Reason, len(all))
			}
			return
		} else if aerr != nil {
			// Reported and then retried the old way: a control plane that has the route and could not answer it
			// is a real failure, and falling straight through would hide it behind a second request.
			log.Printf("agent-rollout sync: asking for every organization's plan failed (%v) — falling back to "+
				"this edge's own", aerr)
		}
		p, err := s.fetch(ctx)
		if err != nil {
			cache.fail(err)
			log.Printf("agent-rollout sync: pull failed (keeping cache): %v", err)
			return
		}
		prev, had, _ := cache.Get()
		cache.setForTenant(s.tenantID, p)
		switch {
		case first:
			first = false
			log.Printf("agent-rollout sync: first pull succeeded — frozen=%t reason=%q", p.Frozen, p.Reason)
		case !had || prev.Frozen != p.Frozen || prev.Reason != p.Reason:
			// ★ THE CHANGE IS THE EVENT (2026-08-11). Logging only the first pull made the moment an operator
			// actually cares about — the halt arriving, or being lifted — invisible: they author a freeze on the
			// control plane and nothing on the enforcing edge says it landed. "It is working" and "it stopped
			// working" would look the same in this log until a device happened to ask.
			log.Printf("agent-rollout sync: the halt CHANGED — frozen=%t reason=%q (was frozen=%t)",
				p.Frozen, p.Reason, prev.Frozen)
		}
	}
	pull()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pull()
		}
	}
}

// agentRolloutCacheOrNil gives an enforcing Edge a cache to pull into, and gives a control plane nil — which
// is what tells the admin write path which of the two it is talking to.
func agentRolloutCacheOrNil(sourceURL string) *agentRolloutCache {
	if strings.TrimSpace(sourceURL) == "" {
		return nil
	}
	return &agentRolloutCache{}
}
