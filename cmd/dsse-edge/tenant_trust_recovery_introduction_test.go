package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCanonicalRecoveryIntroductionSurvivesUnrelatedChangesAndRestart(t *testing.T) {
	d, tr := trustDistributorFixture(t)
	d.config.RenewalRecoverySNI = "recovery.dsse.invalid"
	d.now = func() time.Time { return time.Unix(1700000000, 0) }
	first := publishTrustForTest(t, d, tr)
	original := first["tenant_a"].RecoveryNameSince
	if original == 0 || original != trustPayloadForTest(t, d, first["tenant_a"]).Serial {
		t.Fatal("new name has no exact introduction")
	}
	if _, err := tr.EnsureCA("tenant_b", "b.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	next := publishTrustForTest(t, d, tr)
	if next["tenant_b"].RecoveryNameSince <= original {
		t.Fatal("tenant B did not get its own introduction")
	}
	if _, err := tr.RotateCA("tenant_b"); err != nil {
		t.Fatal(err)
	}
	publishTrustForTest(t, d, tr)
	if _, err := tr.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	restarted := &tenantTrustDistributor{config: d.config, store: d.store, now: func() time.Time { return time.Unix(1, 0) }}
	next = publishTrustForTest(t, restarted, tr)
	if next["tenant_a"].RecoveryNameSince != original || trustPayloadForTest(t, d, next["tenant_a"]).Serial <= original {
		t.Fatal("root change or restart moved the first introduction")
	}
	keys := []string{d.config.AgentPolicySigner.PublicKeyHex()}
	cache := &tenantTrustDistributionCache{keys: keys}
	if err := cache.Adopt(next); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tenant, name string
		want         int64
	}{
		{"tenant_a", "recovery.a.dsse.invalid", original},
		{"tenant_b", "recovery.b.dsse.invalid", next["tenant_b"].RecoveryNameSince},
		{"tenant_a", "recovery.b.dsse.invalid", 0},
		{"missing", "recovery.a.dsse.invalid", 0},
	} {
		if got := canonicalRecoveryNameSince(cache, nil, keys, tc.tenant, tc.name); got != tc.want {
			t.Fatalf("Edge %s/%s: %d != %d", tc.tenant, tc.name, got, tc.want)
		}
		if got := canonicalRecoveryNameSince(nil, d.store, keys, tc.tenant, tc.name); got != tc.want {
			t.Fatalf("CP %s/%s: %d != %d", tc.tenant, tc.name, got, tc.want)
		}
	}
	// An agent holding the earlier valid bundle is not contradictory merely
	// because the same tenant has since published another root overlap.
	r := recoveryNameReadiness{Name: "recovery.a.dsse.invalid", Holds: []string{"mac"}}
	applyRecoverySerialEvidence(&r, []observedExclusionEntry{{DeviceIdentity: "mac", AdoptedTrustSerial: original}}, canonicalRecoveryNameSince(cache, nil, keys, "tenant_a", r.Name))
	if !r.MayCloseTheDedicatedPort() {
		t.Fatalf("earlier valid adoption rejected: %+v", r)
	}
	// Renaming and withdrawing/reintroducing a name each start a new interval.
	tr.cas["tenant_a"].ServerName = "renamed.dsse.invalid"
	renamed := publishTrustForTest(t, restarted, tr)
	if renamed["tenant_a"].RecoveryNameSince <= original || renamed["tenant_a"].RecoveryNameSince != trustPayloadForTest(t, d, renamed["tenant_a"]).Serial {
		t.Fatal("renamed name retained old introduction")
	}
	if err := cache.Adopt(renamed); err != nil {
		t.Fatal(err)
	}
	skipped := &tenantTrustDistributionCache{keys: keys}
	if err := skipped.Adopt(renamed); err != nil {
		t.Fatal(err)
	}
	restarted.config.RenewalRecoverySNI = ""
	removed := publishTrustForTest(t, restarted, tr)
	if removed["tenant_a"].RecoveryNameSince != 0 {
		t.Fatal("withdrawn name retained an introduction")
	}
	if err := cache.Adopt(removed); err != nil {
		t.Fatal(err)
	}
	restarted.config.RenewalRecoverySNI = d.config.RenewalRecoverySNI
	restored := publishTrustForTest(t, restarted, tr)
	if restored["tenant_a"].RecoveryNameSince <= renamed["tenant_a"].RecoveryNameSince {
		t.Fatal("reintroduced name reused former interval")
	}
	if err := skipped.Adopt(restored); err != nil {
		t.Fatalf("Edge missing the withdrawal could not adopt reintroduction: %v", err)
	}
	if err := cache.Adopt(restored); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalRecoveryLegacyIntroductionRemainsUnknown(t *testing.T) {
	d, tr := trustDistributorFixture(t)
	d.config.RenewalRecoverySNI = "recovery.dsse.invalid"
	first := publishTrustForTest(t, d, tr)
	raw, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	state, err := decodeTenantTrustDistributions(raw)
	if err != nil {
		t.Fatal(err)
	}
	state.RecoveryHistoryVersion = 0
	old := state.Tenants["tenant_a"]
	old.Distribution.RecoveryNameSince = 0
	state.Tenants["tenant_a"] = old
	raw, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.store.Save(raw); err != nil {
		t.Fatal(err)
	}
	legacy := publishTrustForTest(t, d, tr)
	if legacy["tenant_a"].RecoveryNameSince != 0 || trustPayloadForTest(t, d, legacy["tenant_a"]).Serial != trustPayloadForTest(t, d, first["tenant_a"]).Serial {
		t.Fatal("migration fabricated history or a revision")
	}
	if _, err = tr.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	next := publishTrustForTest(t, d, tr)
	if next["tenant_a"].RecoveryNameSince != 0 {
		t.Fatal("unrelated publication fabricated history")
	}
	keys := []string{d.config.AgentPolicySigner.PublicKeyHex()}
	cache := &tenantTrustDistributionCache{keys: keys}
	if err = cache.Adopt(next); err != nil {
		t.Fatal(err)
	}
	if got := canonicalRecoveryNameSince(cache, nil, keys, "tenant_a", "recovery.a.dsse.invalid"); got != 0 {
		t.Fatal("legacy history did not remain unknown")
	}
	// A missing Edge cache must not read through to a newer durable publication.
	tr.cas["tenant_a"].ServerName = "new.dsse.invalid"
	publishTrustForTest(t, d, tr)
	if got := canonicalRecoveryNameSince(&tenantTrustDistributionCache{keys: keys}, d.store, keys, "tenant_a", "recovery.new.dsse.invalid"); got != 0 {
		t.Fatal("unadopted CP state substituted for Edge state")
	}
	if got := canonicalRecoveryNameSince(nil, trustBrokenPersister{load: []byte("bad")}, keys, "tenant_a", "recovery.new.dsse.invalid"); got != 0 {
		t.Fatal("corrupt store yielded a comparison")
	}
}

func TestCanonicalRecoveryCacheRejectsInvalidOrRewrittenHistory(t *testing.T) {
	d, tr := trustDistributorFixture(t)
	d.config.RenewalRecoverySNI = "recovery.dsse.invalid"
	first := publishTrustForTest(t, d, tr)
	good := first["tenant_a"]
	serial := trustPayloadForTest(t, d, good).Serial
	for _, bad := range []int64{-1, serial + 1} {
		item := good
		item.RecoveryNameSince = bad
		c := &tenantTrustDistributionCache{keys: []string{d.config.AgentPolicySigner.PublicKeyHex()}}
		if err := c.Adopt(map[string]tenantTrustDistribution{"tenant_a": item}); err == nil {
			t.Fatal("accepted invalid introduction")
		}
	}
	c := &tenantTrustDistributionCache{keys: []string{d.config.AgentPolicySigner.PublicKeyHex()}}
	if err := c.Adopt(first); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	next := publishTrustForTest(t, d, tr)
	for _, base := range []tenantTrustDistribution{good, next["tenant_a"]} {
		for _, bad := range []int64{0, serial - 1} {
			item := base
			item.RecoveryNameSince = bad
			if err := c.Adopt(map[string]tenantTrustDistribution{"tenant_a": item}); err == nil {
				t.Fatal("accepted rewritten history")
			}
			if got := canonicalRecoveryNameSince(c, nil, nil, "tenant_a", "recovery.a.dsse.invalid"); got != serial {
				t.Fatal("rejected history mutated cache")
			}
		}
	}
	if err := c.Adopt(next); err != nil {
		t.Fatal(err)
	}
	tr.cas["tenant_a"].ServerName = "new.dsse.invalid"
	renamed := publishTrustForTest(t, d, tr)
	item := renamed["tenant_a"]
	item.RecoveryNameSince = serial
	if err := c.Adopt(map[string]tenantTrustDistribution{"tenant_a": item}); err == nil {
		t.Fatal("new name claimed an introduction in a known old bundle")
	}
	d.config.RenewalRecoverySNI = ""
	absent := publishTrustForTest(t, d, tr)
	item = absent["tenant_a"]
	item.RecoveryNameSince = serial
	cold := &tenantTrustDistributionCache{keys: c.keys}
	if err := cold.Adopt(map[string]tenantTrustDistribution{"tenant_a": item}); err == nil {
		t.Fatal("introduction without a name accepted")
	}
	// Persisted corruption cannot be healed by issuing a fresh envelope.
	raw, _ := d.store.Load()
	state, _ := decodeTenantTrustDistributions(raw)
	row := state.Tenants["tenant_a"]
	row.Distribution = item
	state.Tenants["tenant_a"] = row
	raw, _ = json.Marshal(state)
	if err := d.store.Save(raw); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := tr.materialSnapshot()
	if out, err := d.Publish(snapshot, nil); err == nil || out != nil {
		t.Fatal("published despite corrupt durable history")
	}
}

func TestRecoverySerialUnknownOrContradictoryCannotClosePort(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		floor, reported        int64
		unknown, contradictory bool
	}{
		{"unknown introduction", 0, 100, true, false},
		{"unknown adoption", 100, 0, true, false},
		{"contradictory", 100, 99, false, true},
		{"first", 100, 100, false, false},
		{"later", 100, 200, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := recoveryNameReadiness{Name: "recovery.a.dsse.invalid", Holds: []string{"mac"}}
			applyRecoverySerialEvidence(&r, []observedExclusionEntry{{DeviceIdentity: "mac", AdoptedTrustSerial: tc.reported}}, tc.floor)
			if (len(r.SerialUnverified) > 0) != tc.unknown || (len(r.Contradicting) > 0) != tc.contradictory {
				t.Fatalf("wrong evidence classification: %+v", r)
			}
			allowed := !tc.unknown && !tc.contradictory
			if r.MayCloseTheDedicatedPort() != allowed || strings.Contains(r.Line(), "may close") != allowed {
				t.Fatalf("wrong port verdict: %s", r.Line())
			}
		})
	}
}

func TestRecoveryFleetReportIncludesUnverifiedEvidenceOnce(t *testing.T) {
	previous := recoveryReadinessSnapshot.Load()
	t.Cleanup(func() { recoveryReadinessSnapshot.Store(previous) })
	snapshot := func() any {
		return recoveryNameReadiness{
			Name: "recovery.dsse.invalid", Silent: []string{"offline"}, NeverReportedAnything: []string{"offline"},
			Contradicting: []string{"older"}, SerialUnverified: []string{"unknown"},
		}
	}
	recoveryReadinessSnapshot.Store(&snapshot)
	name, count := recoveryWayBackForReport()
	if name != "recovery.dsse.invalid" || count != 3 {
		t.Fatalf("fleet hid uncertainty or double-counted silence: %q %d", name, count)
	}
}
