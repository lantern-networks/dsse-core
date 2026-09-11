package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	delegatedgrant "github.com/lantern-networks/dsse-core/delegatedgrant"
	dnsresolver "github.com/lantern-networks/dsse-core/dnsresolver"
	enrolledinventory "github.com/lantern-networks/dsse-core/enrolledinventory"
	nhi "github.com/lantern-networks/dsse-core/nhi"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/vlan"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// Phase 1 config distribution (slice 1): a control-plane policy store serves GET /admin/config-bundle and an
// Edge policy store pulls it and applies it via ReplaceTenant, so the Edge enforces the CP's authoritative
// policy set. Proves: baseline sync, generation-advances-on-change, atomic replace, and fail-safe.
func TestConfigBundleSyncPullsPoliciesFromControlPlane(t *testing.T) {
	const tenant = "tenant_test_cfgsync"
	now := time.Now()
	pol := func(id, family, decision string) model.Policy {
		return model.Policy{ID: id, TenantID: tenant, Priority: 1,
			Conditions: map[string]any{"service_family": family},
			Action:     model.PolicyAction{Decision: decision}, Status: "active"}
	}

	cp := policy.NewStore(nil)
	if _, err := cp.Upsert(context.Background(), pol("pol-a", "ssh", "deny"), tenant, now); err != nil {
		t.Fatalf("cp upsert pol-a: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(configBundlePayload{
			Generation: cp.ConfigGeneration(),
			Policies:   cp.Snapshot(tenant),
		})
	}))
	defer srv.Close()

	edge := policy.NewStore(nil)
	src := configBundleSource{url: srv.URL, token: "t", tenantID: tenant, interval: time.Hour, client: srv.Client()}

	// 1) baseline: first pull applies the CP's set to a fresh Edge.
	p1, err := src.fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch 1: %v", err)
	}
	if p1.Generation == 0 {
		t.Fatalf("expected generation > 0 after a CP upsert")
	}
	if n, _ := src.apply(p1, configApplyTargets{policyStore: edge}); n != 1 {
		t.Fatalf("applied %d policies, want 1", n)
	}
	if _, ok, _ := edge.Get(context.Background(), tenant, "pol-a"); !ok {
		t.Fatalf("edge is missing pol-a after baseline sync")
	}

	// 2) a CP change advances the generation; the next pull applies it.
	if _, err := cp.Upsert(context.Background(), pol("pol-b", "rdp", "allow"), tenant, now); err != nil {
		t.Fatalf("cp upsert pol-b: %v", err)
	}
	p2, err := src.fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch 2: %v", err)
	}
	if p2.Generation <= p1.Generation {
		t.Fatalf("generation did not advance: %d <= %d", p2.Generation, p1.Generation)
	}
	_, _ = src.apply(p2, configApplyTargets{policyStore: edge})
	if _, ok, _ := edge.Get(context.Background(), tenant, "pol-b"); !ok {
		t.Fatalf("edge is missing pol-b after second sync")
	}

	// 3) atomic replace: a policy no longer in the CP snapshot is dropped on the Edge.
	edge.ReplaceTenant(tenant, []model.Policy{pol("pol-b", "rdp", "allow")}, now)
	if _, ok, _ := edge.Get(context.Background(), tenant, "pol-a"); ok {
		t.Fatalf("pol-a should have been replaced out of the edge store")
	}
	if _, ok, _ := edge.Get(context.Background(), tenant, "pol-b"); !ok {
		t.Fatalf("pol-b should remain after replace")
	}
}

// The fleet-health / staleness signal must report the LAST CP GENERATION an Edge applied (not its own local
// store counter, which diverges on every ReplaceTenant). A successful no-op poll stays healthy; an error is
// surfaced without clobbering the last-applied generation.
func TestConfigBundleSyncStatusReportsAppliedCPGeneration(t *testing.T) {
	st := &configBundleSyncStatus{source: "https://cp", interval: 10 * time.Second}

	// before any apply: enabled, not yet applied.
	if snap := st.snapshot(); snap["enabled"] != true || snap["have_applied"] != false {
		t.Fatalf("fresh status: %+v", snap)
	}

	// applying CP generation 7 is what the fleet-health check compares against.
	st.recordApplied(7, "epoch-1", 3, time.Now().UTC())
	snap := st.snapshot()
	if snap["last_applied_generation"].(uint64) != 7 || snap["have_applied"] != true {
		t.Fatalf("after apply gen 7: %+v", snap)
	}
	if snap["last_applied_count"].(int) != 3 {
		t.Fatalf("expected applied count 3, got %+v", snap["last_applied_count"])
	}

	// a healthy no-op poll updates last_poll_at but NOT the applied generation.
	st.recordPoll(time.Now().UTC())
	if g := st.snapshot()["last_applied_generation"].(uint64); g != 7 {
		t.Fatalf("no-op poll must not change applied generation, got %d", g)
	}

	// an error is surfaced but the last-applied generation is preserved (fail-safe).
	st.recordError(fmt.Errorf("control plane unreachable"), time.Now().UTC())
	snap = st.snapshot()
	if snap["last_error"] != "control plane unreachable" {
		t.Fatalf("expected last_error surfaced, got %+v", snap["last_error"])
	}
	if snap["last_applied_generation"].(uint64) != 7 {
		t.Fatalf("a failed poll must keep the last-applied generation, got %+v", snap["last_applied_generation"])
	}

	// a nil status (authoritative-local Edge) reports disabled, never panics.
	var nilStatus *configBundleSyncStatus
	if snap := nilStatus.snapshot(); snap["enabled"] != false {
		t.Fatalf("nil status should be disabled, got %+v", snap)
	}
	nilStatus.recordApplied(1, "epoch-1", 1, time.Now()) // must not panic
}

// The bundle distributes the admin-config TOGGLES that live alongside policies (east-west,
// server-initiated + legacy exceptions, SWG tenant-restriction status) — not just policies. A change to any
// of them advances the generation (so Edges re-pull) and ApplyBundle swaps them in atomically with policies.
func TestConfigBundleSyncDistributesTenantConfig(t *testing.T) {
	const tenant = "tenant_cfg_toggles"
	now := time.Now()
	cp := policy.NewStore(nil)
	if _, err := cp.Upsert(context.Background(), model.Policy{ID: "p1", TenantID: tenant, Priority: 1,
		Conditions: map[string]any{"service_family": "ssh"}, Action: model.PolicyAction{Decision: "deny"}, Status: "active"}, tenant, now); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	genBefore := cp.ConfigGeneration()

	// Admin config changes on the CP each advance the generation (so an Edge knows to re-pull).
	cp.SetEastWestEnabled(tenant, true)
	cp.SetEastWestRules(tenant, []decision.EastWestRule{{ID: "ew1", Mode: "deny"}})
	cp.SetServerInitiatedEnabled(tenant, true)
	cp.UpsertLegacyException(tenant, model.LegacyException{ID: "lx1", Status: "active"})
	cp.SetTenantRestrictionRuleStatus("swg-rule-7", "inactive")
	if cp.ConfigGeneration() <= genBefore {
		t.Fatalf("config-toggle changes must advance the generation: %d <= %d", cp.ConfigGeneration(), genBefore)
	}

	// The bundle the CP serves carries those toggles.
	payload := configBundlePayload{Generation: cp.ConfigGeneration(), Policies: cp.Snapshot(tenant)}
	cfg := cp.SnapshotTenantConfig(tenant)
	payload.TenantConfig = &cfg

	// A fresh Edge applies the whole bundle and now reflects every toggle (and the policy).
	edge := policy.NewStore(nil)
	src := configBundleSource{tenantID: tenant}
	_, _ = src.apply(payload, configApplyTargets{policyStore: edge})

	if _, ok, _ := edge.Get(context.Background(), tenant, "p1"); !ok {
		t.Fatalf("edge missing policy p1 after ApplyBundle")
	}
	if !edge.EastWestIsEnabled(tenant) {
		t.Fatalf("east-west enabled did not distribute")
	}
	if rules := edge.EastWestRulesFor(tenant); len(rules) != 1 || rules[0].ID != "ew1" {
		t.Fatalf("east-west rules did not distribute: %+v", rules)
	}
	if exs := edge.LegacyExceptionsFor(tenant); len(exs) != 1 || exs[0].ID != "lx1" {
		t.Fatalf("legacy exceptions did not distribute: %+v", exs)
	}
	if got := edge.TenantRestrictionRuleStatusOverrides()["swg-rule-7"]; got != "inactive" {
		t.Fatalf("SWG tenant-restriction status did not distribute: %q", got)
	}

	// Fail-safe: a bundle WITHOUT tenant_config (older CP) must NOT clear the Edge's existing toggles.
	_, _ = src.apply(configBundlePayload{Generation: payload.Generation + 1, Policies: cp.Snapshot(tenant)}, configApplyTargets{policyStore: edge})
	if !edge.EastWestIsEnabled(tenant) {
		t.Fatalf("a tenant_config-less bundle must not clear existing config (fail-safe)")
	}
}

func cfgTestContains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// DNS policy lives in a SEPARATE store (the dnsresolver.Resolver, not policy.Store), so the bundle distributes it
// via the top-level dns_policy field and the bundle's generation is the SUM of the two stores' generations.
// Proves: a setPolicy advances the DNS generation; the bundle's DNS policy is applied to the Edge's resolver;
// and a bundle WITHOUT dns_policy leaves the Edge's DNS policy untouched (fail-safe).
func TestConfigBundleDistributesDNSPolicy(t *testing.T) {
	const tenant = "tenant_dns"
	cpDNS := dnsresolver.NewWithUpstream(tenant, nil, nil)
	echOn := true
	cpPol, _ := dnsresolver.PolicyFromDTO(dnsresolver.PolicyDTO{Deny: []string{"evil.example"}, ECHStrip: &echOn})
	cpDNS.SetPolicy(cpPol)
	if cpDNS.ConfigGeneration() == 0 {
		t.Fatalf("setPolicy must advance the DNS generation")
	}
	dto := dnsresolver.PolicyToDTO(cpDNS.CurrentPolicy())

	edgeDNS := dnsresolver.NewWithUpstream(tenant, nil, nil)
	edgePolicy := policy.NewStore(nil)
	src := configBundleSource{tenantID: tenant}

	_, _ = src.apply(configBundlePayload{DNSPolicy: &dto}, configApplyTargets{policyStore: edgePolicy, resolver: edgeDNS})
	gotDTO := dnsresolver.PolicyToDTO(edgeDNS.CurrentPolicy())
	if len(gotDTO.Deny) == 0 || gotDTO.Deny[0] != "evil.example" {
		t.Fatalf("DNS deny did not distribute: %+v", gotDTO)
	}
	if gotDTO.ECHStrip == nil || !*gotDTO.ECHStrip {
		t.Fatalf("DNS ech_strip did not distribute")
	}

	// Fail-safe: a bundle WITHOUT dns_policy must not clear the Edge's DNS policy.
	_, _ = src.apply(configBundlePayload{}, configApplyTargets{policyStore: edgePolicy, resolver: edgeDNS})
	if d := dnsresolver.PolicyToDTO(edgeDNS.CurrentPolicy()).Deny; len(d) == 0 || d[0] != "evil.example" {
		t.Fatalf("a dns_policy-less bundle must not clear the DNS policy (fail-safe)")
	}

	// A nil resolver (Edge has no DNS resolver) must not panic.
	_, _ = src.apply(configBundlePayload{DNSPolicy: &dto}, configApplyTargets{policyStore: edgePolicy})
}

// The Enrolled Inventory (admission allowlist) is a separate store (enrolledinventory.Ledger); the
// bundle distributes the whole set so admission is consistent fleet-wide. Proves: enroll/disable advance the
// generation; the set distributes (enabled => admitted, disabled => not); a removal distributes; and a bundle
// WITHOUT the enrolled section leaves the Edge ledger untouched (fail-safe).
func TestConfigBundleDistributesEnrolledInventory(t *testing.T) {
	nowStr := time.Now().UTC().Format(time.RFC3339)
	cp := enrolledinventory.NewLedger()
	cp.Enroll("dev-a", "tenant_x", "", nowStr)
	cp.Enroll("dev-b", "tenant_x", "", nowStr)
	cp.SetEnabled("dev-b", false, nowStr) // disabled = the manual revocation path (distributed at config latency)
	if cp.ConfigGeneration() == 0 {
		t.Fatalf("enroll/disable must advance the enrolled generation")
	}

	edgeLedger := enrolledinventory.NewLedger()
	edgePolicy := policy.NewStore(nil)
	src := configBundleSource{tenantID: "tenant_x"}
	targets := configApplyTargets{policyStore: edgePolicy, enrolled: edgeLedger}

	_, _ = src.apply(configBundlePayload{Enrolled: &enrolledInventoryBundle{Entries: cp.List()}}, targets)
	if !edgeLedger.IsAdmitted("dev-a") {
		t.Fatalf("dev-a (enabled) should be admitted after distribution")
	}
	if edgeLedger.IsAdmitted("dev-b") {
		t.Fatalf("dev-b (disabled) must NOT be admitted")
	}

	// A removal on the CP distributes: the Edge drops dev-a.
	cp.Remove("dev-a", "2026-08-24T00:00:00Z")
	_, _ = src.apply(configBundlePayload{Enrolled: &enrolledInventoryBundle{Entries: cp.List()}}, targets)
	if edgeLedger.IsAdmitted("dev-a") {
		t.Fatalf("dev-a should be removed from the Edge after distribution")
	}

	// Fail-safe: a bundle WITHOUT the enrolled section must NOT clear the Edge ledger.
	_, _ = src.apply(configBundlePayload{}, targets)
	if len(edgeLedger.List()) == 0 {
		t.Fatalf("an enrolled-less bundle must not clear the ledger (fail-safe)")
	}
}

// VLAN objects + boundary policies are a separate store (vlan.Store); the bundle distributes
// the whole set so the firewall-export policy authority is consistent fleet-wide. Proves: upsert advances the
// generation; objects + policies distribute; a vlan-less bundle leaves the Edge untouched (fail-safe).
func TestConfigBundleDistributesVLANBoundary(t *testing.T) {
	cp := vlan.NewStore()
	if _, err := cp.UpsertObject(model.VLANObject{ID: "obj-srv", Class: "server", CIDRs: []string{"10.0.0.0/24"}}); err != nil {
		t.Fatalf("upsert object: %v", err)
	}
	if _, err := cp.UpsertPolicy(model.VLANBoundaryPolicy{ID: "pol-1", SourceClass: "managed_endpoint", DestClass: "server", Mode: "deny", ServiceFamily: "smb"}); err != nil {
		t.Fatalf("upsert policy: %v", err)
	}
	if cp.ConfigGeneration() == 0 {
		t.Fatalf("VLAN upserts must advance the generation")
	}

	edgeVLAN := vlan.NewStore()
	edgePolicy := policy.NewStore(nil)
	src := configBundleSource{tenantID: "t"}
	targets := configApplyTargets{policyStore: edgePolicy, vlan: edgeVLAN}

	_, _ = src.apply(configBundlePayload{VLAN: &vlanBoundaryBundle{Objects: cp.ListObjects(), Policies: cp.ListPolicies()}}, targets)
	if objs := edgeVLAN.ListObjects(); len(objs) != 1 || objs[0].ID != "obj-srv" {
		t.Fatalf("VLAN objects did not distribute: %+v", objs)
	}
	if pols := edgeVLAN.ListPolicies(); len(pols) != 1 || pols[0].ID != "pol-1" {
		t.Fatalf("VLAN policies did not distribute: %+v", pols)
	}

	// Fail-safe: a bundle WITHOUT the vlan section must not clear the Edge's set.
	_, _ = src.apply(configBundlePayload{}, targets)
	if len(edgeVLAN.ListObjects()) == 0 {
		t.Fatalf("a vlan-less bundle must not clear the VLAN store (fail-safe)")
	}
}

// LOCKOUT-SAFE GUARD (regression for the 2026-06-20 incident): a control plane that is not the authority for
// a section serves it PRESENT-but-EMPTY (every Edge binary always constructs the stores). A blind replace
// would wipe non-empty enforcement state into an availability cliff — empty enrolled = admission lockout,
// empty policies = default-deny-all, empty VLAN = inter-VLAN enforcement dropped. apply must KEEP the
// non-empty local set when the pulled section is present-but-empty. (A present section WITH content still
// replaces — proven by the distribute tests above; this proves the empty direction does not wipe.)
func TestConfigBundleEmptySectionDoesNotWipeNonEmptyLocal(t *testing.T) {
	const tenant = "tenant_lockout_safe"
	now := time.Now()
	nowStr := now.UTC().Format(time.RFC3339)
	pol := model.Policy{ID: "pol-keep", TenantID: tenant, Priority: 1,
		Conditions: map[string]any{"service_family": "ssh"},
		Action:     model.PolicyAction{Decision: "allow"}, Status: "active"}

	edgePolicy := policy.NewStore(nil)
	edgePolicy.ReplaceTenant(tenant, []model.Policy{pol}, now)
	edgeLedger := enrolledinventory.NewLedger()
	edgeLedger.Enroll("dev-a", tenant, "", nowStr)
	edgeVLAN := vlan.NewStore()
	if _, err := edgeVLAN.UpsertObject(model.VLANObject{ID: "obj-keep", Class: "server", CIDRs: []string{"10.0.0.0/24"}}); err != nil {
		t.Fatalf("seed vlan: %v", err)
	}
	// DNS was the one distributed section with no such guard, and the reason it went unnoticed for so long is
	// that this test — the test whose whole job is this rule — did not cover it. A gap in enforcement and a gap
	// in the test that would have caught it are usually the same gap.
	edgeDNS := dnsresolver.NewWithUpstream(tenant, nil, nil)
	seedDNS, err := dnsresolver.PolicyFromDTO(dnsresolver.PolicyDTO{StubIPv4: map[string]string{"app.corp": "100.64.0.9"}})
	if err != nil {
		t.Fatalf("seed dns policy: %v", err)
	}
	edgeDNS.SetPolicy(seedDNS)

	src := configBundleSource{tenantID: tenant}
	targets := configApplyTargets{policyStore: edgePolicy, enrolled: edgeLedger, vlan: edgeVLAN, resolver: edgeDNS}

	// A bundle with EVERY distributed section present-but-EMPTY (what a non-authoritative CP serves).
	_, _ = src.apply(configBundlePayload{
		Policies:  []model.Policy{},
		Enrolled:  &enrolledInventoryBundle{Entries: []enrolledinventory.Entry{}},
		VLAN:      &vlanBoundaryBundle{Objects: []model.VLANObject{}, Policies: []model.VLANBoundaryPolicy{}},
		DNSPolicy: &dnsresolver.PolicyDTO{},
	}, targets)

	if edgeDNS.CurrentPolicy().IsEmpty() {
		t.Fatalf("empty DNS section wiped the local DNS policy — internal names stop resolving, which reaches a user as a browser reporting no internet")
	}

	if _, ok, _ := edgePolicy.Get(context.Background(), tenant, "pol-keep"); !ok {
		t.Fatalf("empty policies wiped the local policy set (fleet-wide default-deny) — guard failed")
	}
	if !edgeLedger.IsAdmitted("dev-a") {
		t.Fatalf("empty enrolled section wiped the local admission ledger (lockout) — guard failed")
	}
	if len(edgeVLAN.ListObjects()) == 0 {
		t.Fatalf("empty VLAN section wiped the local boundary set — guard failed")
	}
}

// /agent governance: the Non-Human Identity registry (nhi.Store) and delegated-access grants
// (delegatedgrant.Store) are separate stores; the bundle distributes them so agent governance authored on the
// control plane reaches enforcing Edges. Proves: upsert advances each store's generation; both sections
// distribute (UPSERT); and a bundle with EMPTY sections + non-empty local stores keeps local (lockout-safe).
func TestConfigBundleDistributesNHIAndDelegatedGrants(t *testing.T) {
	const tenant = "tenant_agentgov"
	now := time.Now().UTC()
	ctx := context.Background()

	// CP: register an NHI + a delegated grant (each advances its store generation).
	cpNHI := nhi.NewStore()
	if _, err := cpNHI.Upsert(ctx, model.NonHumanIdentity{ID: "nhi-a", Name: "Agent A", NHIType: "ai_agent", OwnerUserID: "u1"}, tenant, now); err != nil {
		t.Fatalf("cp nhi upsert: %v", err)
	}
	if cpNHI.ConfigGeneration() == 0 {
		t.Fatalf("NHI upsert must advance the registry generation")
	}
	cpGrants := delegatedgrant.NewStore(0)
	if _, err := cpGrants.Upsert(model.DelegatedAccessGrant{ID: "grant-a", TenantID: tenant, SubjectUserID: "u1", ActorNHIID: "nhi-a",
		Scopes: []string{"read"}, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Status: "active"}); err != nil {
		t.Fatalf("cp grant upsert: %v", err)
	}
	if cpGrants.ConfigGeneration() == 0 {
		t.Fatalf("delegated-grant upsert must advance the generation")
	}

	// A fresh Edge applies the bundle and receives both entries (UPSERT).
	edgeNHI := nhi.NewStore()
	edgeGrants := delegatedgrant.NewStore(0)
	edgePolicy := policy.NewStore(nil)
	src := configBundleSource{tenantID: tenant}
	targets := configApplyTargets{policyStore: edgePolicy, nhi: edgeNHI, delegatedGrants: edgeGrants}

	cpIdentities, _ := cpNHI.List(ctx, tenant)
	_, _ = src.apply(configBundlePayload{
		NHI:             &nonHumanIdentityBundle{Identities: cpIdentities},
		DelegatedGrants: &delegatedGrantBundle{Grants: cpGrants.Snapshot()},
	}, targets)

	if got, _ := edgeNHI.List(ctx, tenant); len(got) != 1 || got[0].ID != "nhi-a" {
		t.Fatalf("NHI did not distribute: %+v", got)
	}
	if _, ok := edgeGrants.Get("grant-a"); !ok {
		t.Fatalf("delegated grant did not distribute")
	}

	// Lockout-safe: a bundle with EMPTY sections must NOT wipe the non-empty local stores.
	_, _ = src.apply(configBundlePayload{
		NHI:             &nonHumanIdentityBundle{Identities: []model.NonHumanIdentity{}},
		DelegatedGrants: &delegatedGrantBundle{Grants: []model.DelegatedAccessGrant{}},
	}, targets)
	if got, _ := edgeNHI.List(ctx, tenant); len(got) != 1 {
		t.Fatalf("empty NHI section wiped the local registry (lockout) — guard failed: %+v", got)
	}
	if _, ok := edgeGrants.Get("grant-a"); !ok {
		t.Fatalf("empty delegated-grant section wiped the local grant set (lockout) — guard failed")
	}

	// Fail-safe: a bundle WITHOUT either section (nil) must not clear the Edge stores.
	_, _ = src.apply(configBundlePayload{}, targets)
	if got, _ := edgeNHI.List(ctx, tenant); len(got) != 1 {
		t.Fatalf("an nhi-less bundle must not clear the registry (fail-safe)")
	}
	if _, ok := edgeGrants.Get("grant-a"); !ok {
		t.Fatalf("a grant-less bundle must not clear the grant set (fail-safe)")
	}
}

// The aggregate generation is in-memory and resets when the control plane restarts; without the epoch a
// still-running puller (last-applied gen N) would see the reset gen <= N and FREEZE its config. The epoch
// lets the puller detect a CP restart and re-baseline regardless of generation.
func TestShouldApplyBundleHandlesControlPlaneRestart(t *testing.T) {
	const epochA, epochB = "epoch-A", "epoch-B"
	cases := []struct {
		name        string
		haveApplied bool
		lastEpoch   string
		lastApplied uint64
		payload     configBundlePayload
		want        bool
	}{
		{"first pull always applies", false, "", 0, configBundlePayload{Epoch: epochA, Generation: 5}, true},
		{"same epoch newer gen applies", true, epochA, 3, configBundlePayload{Epoch: epochA, Generation: 4}, true},
		{"same epoch equal gen no-op", true, epochA, 3, configBundlePayload{Epoch: epochA, Generation: 3}, false},
		{"same epoch older gen no-op", true, epochA, 3, configBundlePayload{Epoch: epochA, Generation: 2}, false},
		// THE FIX: the CP restarted (epoch changed) and its generation reset BELOW ours — must re-baseline.
		{"restart with lower gen re-baselines", true, epochA, 3, configBundlePayload{Epoch: epochB, Generation: 0}, true},
		{"restart with equal gen re-baselines", true, epochA, 3, configBundlePayload{Epoch: epochB, Generation: 3}, true},
	}
	for _, c := range cases {
		if got := shouldApplyBundle(c.haveApplied, c.lastEpoch, c.lastApplied, c.payload); got != c.want {
			t.Fatalf("%s: shouldApplyBundle = %v, want %v", c.name, got, c.want)
		}
	}
}

// fail-safe: a pull error must not panic and must leave the caller free to keep the existing config.
func TestConfigBundleSyncFailSafeOnUnreachableSource(t *testing.T) {
	const tenant = "tenant_test_failsafe"
	edge := policy.NewStore(nil)
	edge.ReplaceTenant(tenant, []model.Policy{{ID: "keep", TenantID: tenant, Priority: 1,
		Conditions: map[string]any{"service_family": "https"}, Action: model.PolicyAction{Decision: "allow"}, Status: "active"}}, time.Now())

	src := configBundleSource{url: "https://127.0.0.1:1", token: "t", tenantID: tenant, interval: time.Hour,
		client: &http.Client{Timeout: time.Second}}
	if _, err := src.fetch(context.Background()); err == nil {
		t.Fatalf("expected an error from an unreachable source")
	}
	// the existing config is untouched
	if _, ok, _ := edge.Get(context.Background(), tenant, "keep"); !ok {
		t.Fatalf("existing config must survive a failed pull")
	}
}

// ★★ DELETING THE LAST NAMED NETWORK HAD TO BE POSSIBLE, AND WAS NOT (2026-08-16, measured on the lab).
// The lockout-safe guard above refused every empty VLAN payload, so an operator who removed the last object on
// the control plane got a 200, saw an empty list there, and the object stayed on the enforcing Edge — with
// nothing able to remove it, because the Edge refuses its own DELETE with 409 ("authored on the control
// plane") and the control plane no longer had it to delete.
//
// The fix is the one this codebase already uses for tenant deletion: carry the fact instead of inferring it.
// Both halves are asserted here, because either alone is a regression: an empty-and-complete set MUST clear,
// and an empty set from a control plane that cannot vouch for it MUST NOT.
func TestAnEmptyVLANSetClearsTheEdgeOnlyWhenTheControlPlaneSaysItIsComplete(t *testing.T) {
	seed := func() *vlan.Store {
		s := vlan.NewStore()
		if _, err := s.UpsertObject(model.VLANObject{ID: "obj-keep", Class: "server", CIDRs: []string{"10.0.0.0/24"}}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		return s
	}
	src := configBundleSource{tenantID: "t"}

	// 1. An empty set the control plane cannot vouch for (in-memory store) must not wipe enforcement.
	unsure := seed()
	_, _ = src.apply(configBundlePayload{VLAN: &vlanBoundaryBundle{}}, configApplyTargets{vlan: unsure})
	if len(unsure.ListObjects()) != 1 {
		t.Fatalf("an empty-but-unvouched VLAN set must keep the local enforcement, got %+v", unsure.ListObjects())
	}

	// 2. An empty set the control plane STATES is complete must clear it, or the last object is undeletable.
	sure := seed()
	_, _ = src.apply(configBundlePayload{VLAN: &vlanBoundaryBundle{Complete: true}}, configApplyTargets{vlan: sure})
	if got := sure.ListObjects(); len(got) != 0 {
		t.Fatalf("a complete-and-empty VLAN set must clear the Edge, got %+v", got)
	}

	// 3. A control plane only says "complete" when its own store is durable. An in-memory one that has just
	//    restarted is empty for a reason that is not "there are none".
	if vlan.NewStore().Persisted() {
		t.Fatalf("an in-memory store must not claim to be persisted — the distributor reads this to decide whether it may say its set is complete")
	}
}
