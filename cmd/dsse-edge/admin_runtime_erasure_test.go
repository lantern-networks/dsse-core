package main

import (
	"context"
	"github.com/lantern-networks/dsse-core/policy"
	"testing"
)

func TestPostgresRuntimeErasureKeepsAcceptedTerm(t *testing.T) {
	d, _, leader, peer := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "test_runtime_erasure"
	defer p.db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	s := policy.NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	enabled := true
	value := "example.invalid"
	for _, tenant := range []string{"target", "peer"} {
		if err := s.SaveTenantRestrictionContext(captureCPWriteLease(context.Background()), tenant, "google_workspace", policy.TenantRestrictionPatch{Enabled: &enabled, AllowedValue: &value}); err != nil {
			t.Fatal(err)
		}
	}
	old := captureCPWriteLease(context.Background())
	leader.release()
	peer.tick()
	if !peer.IsLeader() {
		t.Fatal("no successor")
	}
	cpLeaderElectorInstance = peer
	extra := adminTenantExtraStores{TenantRestrictions: s}
	result := adminTenantPurgeResult{TenantID: "target"}
	extra.eraseContext(old, &result)
	if len(result.Failures) == 0 || s.CountTenantRestrictions("target") != 1 {
		t.Fatalf("old accepted term erased configuration: %+v", result)
	}
	canceled, cancel := context.WithCancel(captureCPWriteLease(context.Background()))
	cancel()
	result = adminTenantPurgeResult{TenantID: "target"}
	extra.eraseContext(canceled, &result)
	if len(result.Failures) == 0 || s.CountTenantRestrictions("target") != 1 {
		t.Fatal("canceled erasure applied")
	}
	result = adminTenantPurgeResult{TenantID: "target"}
	extra.eraseContext(captureCPWriteLease(context.Background()), &result)
	if len(result.Failures) != 0 {
		t.Fatal(result.Failures)
	}
	fresh := policy.NewStore(nil)
	if err := fresh.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	if fresh.CountTenantRestrictions("target") != 0 || fresh.CountTenantRestrictions("peer") != 1 {
		t.Fatal("target survived or peer lost")
	}
}
