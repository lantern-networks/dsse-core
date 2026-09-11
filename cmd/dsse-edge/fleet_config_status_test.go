package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The question the Console could not ask on 2026-08-10: "which Edges actually have this?"
//
// The incident was not that a write failed — it succeeded, persisted, compiled, and was reported correctly by
// the Edge that was asked, while the device was served by another Edge that had never heard of it. Every
// property below is one the operator needed that day and could not get.
func TestFleetConfigStatusAnswersWhichEdgesHaveTheCurrentConfig(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	s := newFleetConfigStatusStore(10 * time.Second)

	s.Record(fleetConfigReport{RegionID: "region-a", ClusterID: "c1", Generation: 42, Epoch: "e1", HaveApplied: true, RuleCount: 3}, now)
	s.Record(fleetConfigReport{RegionID: "region-b", ClusterID: "c1", Generation: 41, Epoch: "e1", HaveApplied: true, RuleCount: 2}, now)

	got := map[string]string{}
	for _, e := range s.List(42, "e1", now) {
		got[e.RegionID] = e.Status
	}
	if got["region-a"] != "current" || got["region-b"] != "lagging" {
		t.Fatalf("an Edge one generation behind must read as lagging, got %+v", got)
	}

	// The exact shape of the incident: region-a has it, region-b does not, so the fleet is NOT in sync — and
	// the API says so once, rather than leaving each reader to decide.
	if inSync := fleetInSync(s.List(42, "e1", now)); inSync {
		t.Fatalf("a fleet where one Edge lags must not report in_sync")
	}

	s.Record(fleetConfigReport{RegionID: "region-b", ClusterID: "c1", Generation: 42, Epoch: "e1", HaveApplied: true, RuleCount: 3}, now)
	if inSync := fleetInSync(s.List(42, "e1", now)); !inSync {
		t.Fatalf("once every Edge reports the current generation the fleet is in sync")
	}
}

// ★ THE FLEET IS WHATEVER IS REPORTING NOW. Instances are created and destroyed continuously, so an instance
// that stops reporting has, overwhelmingly, been REMOVED — and keeping it as a fault turns a routine scale-in
// into "4 Edges, 2 not responding", which also asserts an expected count nothing here knows.
//
// This reverses a first version that kept departed instances for half an hour and counted them as behind. The
// cost of the reversal is stated in the design doc rather than hidden: an instance that is still serving but
// can no longer reach the control plane leaves the view, and the drop in the number is the only signal.
func TestTheFleetIsWhateverIsReportingNow(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	s := newFleetConfigStatusStore(10 * time.Second) // fresh for 3 missed reports = 30s
	s.Record(fleetConfigReport{RegionID: "region-a", ClusterID: "c1", NodeID: "n1", Generation: 42, Epoch: "e1", HaveApplied: true}, now)

	// One missed poll must not change the picture — a blip that made the count flicker would be unreadable.
	if got := s.List(42, "e1", now.Add(15*time.Second)); len(got) != 1 || got[0].Status != "current" {
		t.Fatalf("a single missed report must not remove an instance or change its state: %+v", got)
	}
	// Beyond that it is simply not in the fleet. NOT listed as a fault.
	if got := s.List(42, "e1", now.Add(90*time.Second)); len(got) != 0 {
		t.Fatalf("an instance that stopped reporting is gone, not broken — got %d row(s) still counted", len(got))
	}
}

// Scaling in must not make the remaining fleet look wrong. Three instances become two, and the two that are
// left hold the current configuration, so the answer is "in sync" — not "one is missing".
func TestScaleInLeavesTheRemainingFleetInSync(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	s := newFleetConfigStatusStore(10 * time.Second)
	for _, n := range []string{"n1", "n2", "n3"} {
		s.Record(fleetConfigReport{RegionID: "region-a", ClusterID: "c1", NodeID: n, Generation: 42, Epoch: "e1", HaveApplied: true}, now)
	}
	if !fleetInSync(s.List(42, "e1", now)) {
		t.Fatalf("three current instances are in sync")
	}
	// n3 is scaled away; the survivors keep reporting.
	later := now.Add(90 * time.Second)
	for _, n := range []string{"n1", "n2"} {
		s.Record(fleetConfigReport{RegionID: "region-a", ClusterID: "c1", NodeID: n, Generation: 42, Epoch: "e1", HaveApplied: true}, later)
	}
	got := s.List(42, "e1", later)
	if len(got) != 2 {
		t.Fatalf("after a scale-in the fleet is the two that remain, got %d", len(got))
	}
	if !fleetInSync(got) {
		t.Fatalf("a scale-in must not read as a fault — the fleet that EXISTS holds the current configuration")
	}
}

// An empty fleet is not agreement either. "Nobody has reported" and "everybody agrees" produce the same green
// banner unless the zero case is decided deliberately — the same "absence read as success" shape as the rest
// of this incident.
func TestFleetConfigStatusEmptyIsNotInSync(t *testing.T) {
	s := newFleetConfigStatusStore(10 * time.Second)
	if fleetInSync(s.List(1, "e1", time.Now())) {
		t.Fatalf("no reporting Edges must not read as in_sync")
	}
}

// A control-plane restart re-baselines the generation counter, so numbers across epochs are not comparable.
// Reporting "current" from a stale-epoch number would be a guess presented as a fact.
func TestFleetConfigStatusTreatsADifferentEpochAsLagging(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	s := newFleetConfigStatusStore(10 * time.Second)
	s.Record(fleetConfigReport{RegionID: "region-a", ClusterID: "c1", Generation: 99, Epoch: "old", HaveApplied: true}, now)
	if got := s.List(5, "new", now)[0].Status; got != "lagging" {
		t.Fatalf("a report from a previous CP epoch must not read as current (its number is bigger but unrelated), got %s", got)
	}
}

// An Edge that has never applied anything is distinct from one that is behind: it has no configuration at all,
// which is a different operator action.
func TestFleetConfigStatusDistinguishesNeverApplied(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	s := newFleetConfigStatusStore(10 * time.Second)
	s.Record(fleetConfigReport{RegionID: "region-c", ClusterID: "c1", HaveApplied: false}, now)
	if got := s.List(7, "e1", now)[0].Status; got != "never_applied" {
		t.Fatalf("an Edge that never applied a bundle must say so, got %s", got)
	}
}

// ★ A REGION IS NOT ONE EDGE. Production fronts several behind a load balancer, and keying the view on
// region/cluster alone made them overwrite each other — the view showed ONE row carrying whichever instance
// reported last, so an instance that was BEHIND became invisible the moment a current sibling spoke. One
// member answering for the group: the incident this file exists to end, reproduced inside it.
//
// Measured on the live control plane before the fix: two reports for region-a produced one row, and the
// second (generation 3) replaced the first (generation 99).
func TestEveryInstanceInARegionIsVisibleSeparately(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	s := newFleetConfigStatusStore(10 * time.Second)

	// Two Edges behind one load balancer: same region, same cluster, different processes.
	s.Record(fleetConfigReport{RegionID: "region-a", ClusterID: "c1", NodeID: "edge-1", Generation: 42, Epoch: "e1", HaveApplied: true}, now)
	s.Record(fleetConfigReport{RegionID: "region-a", ClusterID: "c1", NodeID: "edge-2", Generation: 41, Epoch: "e1", HaveApplied: true}, now)

	edges := s.List(42, "e1", now)
	if len(edges) != 2 {
		t.Fatalf("both instances of region-a must be listed, got %d row(s) — a lagging sibling is invisible "+
			"whenever a current one reports after it", len(edges))
	}
	states := map[string]string{}
	for _, e := range edges {
		states[e.NodeID] = e.Status
	}
	if states["edge-1"] != "current" || states["edge-2"] != "lagging" {
		t.Fatalf("each instance must carry its OWN state, got %+v", states)
	}
	if fleetInSync(edges) {
		t.Fatalf("a region with one lagging instance is not in sync — this is exactly the case the old key hid")
	}
}

// ★ THE DASHBOARD A CUSTOMER SEES MUST NOT BE THE DEPLOYMENT'S INVENTORY (2026-08-16, found by signing in as
// one). This route is gated on admin.policy.read, which EVERY tenant administrator holds — the erasure route
// beside it is gated on admin.tenant.admin, and this one was not. Signed in as Northwind's administrator, a
// principal with no cross-tenant permission at all, the reply carried every node's id and cluster, the control
// plane's generation and epoch, each node's rule count across all tenants, and the erasure ledger — which
// names every organization the deployment has ever been told to erase. Thirteen of them, by id.
//
// Both halves are asserted in one run: the operator still gets the whole answer, so a fix that simply emptied
// the route for everybody would fail here rather than look like a pass.
func TestTheFleetAnswerIsScopedToWhoIsAsking(t *testing.T) {
	declareOperatorTenantForTest(t, "tenant_operator_001")
	// The handler judges freshness against time.Now(), so the report must be recorded against it too.
	now := time.Now().UTC()
	store := newFleetConfigStatusStore(10 * time.Minute)
	store.Record(fleetConfigReport{
		RegionID: "region-a", ClusterID: "local-edge-001", NodeID: "39f3eca92319",
		Generation: 7, Epoch: "e1", HaveApplied: true, RuleCount: 12,
		Erasures: []fleetTenantErasure{
			{TenantID: "tenant_northwind", Clean: true},
			{TenantID: "tenant_acme_demo", Clean: true},
			{TenantID: "tenant_lab_001", Clean: false, Remaining: 4},
		},
	}, now)

	mux := http.NewServeMux()
	registerFleetConfigStatusRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		store, func() (uint64, string) { return 7, "e1" })

	call := func(identity adminIdentity) map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/admin/fleet/config-status", nil)
		r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, identity))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("HTTP %d for %+v", rec.Code, identity)
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	// A customer administrator: tenant-scoped roles, no admin.tenant.admin.
	customer := call(adminIdentity{PrincipalID: "adm_nw", TenantID: "tenant_northwind", Roles: []string{"admin"}, AuthMethod: "admin_session"})
	raw, _ := json.Marshal(customer)
	for _, forbidden := range []string{"tenant_acme_demo", "tenant_lab_001", "39f3eca92319", "local-edge-001", "control_plane_epoch", "control_plane_generation", "rule_count"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("a customer was told %q:\n%s", forbidden, raw)
		}
	}
	edges, _ := customer["edges"].([]any)
	if len(edges) != 1 {
		t.Fatalf("a customer must still learn whether their configuration is in effect, got %s", raw)
	}
	row, _ := edges[0].(map[string]any)
	if row["region_id"] != "region-a" || row["status"] != "current" {
		t.Fatalf("the customer's row must carry where and whether, got %+v", row)
	}
	// Their OWN erasure row survives: whether their data is gone is theirs to know.
	ers, _ := row["erasures"].([]any)
	if len(ers) != 1 {
		t.Fatalf("the caller's own erasure row must survive, got %+v", row)
	}
	if own, _ := ers[0].(map[string]any); own["tenant_id"] != "tenant_northwind" {
		t.Fatalf("only the caller's own erasure row may survive, got %+v", ers)
	}

	// The control: the operator still gets everything, or this route has been broken rather than scoped.
	operator := call(adminIdentity{PrincipalID: "adm_op", TenantID: "tenant_operator_001", Roles: []string{"owner"}, AuthMethod: "admin_session"})
	rawOp, _ := json.Marshal(operator)
	for _, needed := range []string{"tenant_acme_demo", "tenant_lab_001", "39f3eca92319", "local-edge-001", "control_plane_epoch", "rule_count"} {
		if !strings.Contains(string(rawOp), needed) {
			t.Fatalf("the operator lost %q — the route was broken, not scoped:\n%s", needed, rawOp)
		}
	}
}
