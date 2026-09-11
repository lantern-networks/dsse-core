package main

import (
	"fmt"
	"testing"

	"github.com/lantern-networks/dsse-core/policy"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// BenchmarkRuntimeEvaluator models the per-flow decision hot path: every CONNECT calls
// store.RuntimeEvaluator(base) to overlay runtime policy/rule state onto the base evaluator.
// Measures cost + allocs of building the live evaluator per flow under concurrency.
func BenchmarkRuntimeEvaluator(b *testing.B) {
	const tenant = "tenant_bench"
	seed := make([]model.Policy, 0, 24)
	for i := 0; i < 24; i++ {
		decision := "allow"
		if i%3 == 0 {
			decision = "deny"
		}
		seed = append(seed, model.Policy{
			ID:       fmt.Sprintf("pol_%02d", i),
			TenantID: tenant,
			Status:   "active",
			Priority: i % 5,
			Action:   model.PolicyAction{Decision: decision},
			Conditions: map[string]any{
				"actor_type":     "human",
				"service_family": "https",
				"destination":    fmt.Sprintf("host-%02d.example.com", i),
			},
		})
	}
	store := policy.NewStore(seed)
	base := decision.Evaluator{
		PolicyBundle: model.PolicyBundle{
			TenantID: tenant,
			SWGTenantRestrictionRules: []model.SWGTenantRestrictionRule{
				{ID: "swg_tr_google_workspace_lab", Status: "active"},
				{ID: "swg_tr_microsoft_365_lab", Status: "active"},
			},
		},
	}
	store.SetTenantRestrictionRuleStatus("swg_tr_google_workspace_lab", "inactive")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ev := store.RuntimeEvaluator(base)
			if len(ev.Policies) == 0 {
				b.Fatal("expected policies")
			}
		}
	})
}
