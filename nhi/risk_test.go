package nhi

import (
	"context"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestComputeNHIRiskSignals(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	soon := now.Add(24 * time.Hour).Format(time.RFC3339)
	farFuture := now.Add(200 * 24 * time.Hour).Format(time.RFC3339)
	recent := now.Add(-1 * time.Hour).Format(time.RFC3339)
	stale := now.Add(-60 * 24 * time.Hour).Format(time.RFC3339)

	cases := []struct {
		name        string
		nhi         model.NonHumanIdentity
		wantSev     string
		wantSignals []string
	}{
		{
			name: "well_governed_is_none",
			nhi: model.NonHumanIdentity{
				OwnerUserID: "alice", ExpiresAt: &soon, LastUsedAt: &recent,
				AllowlistEnforced: true, AllowedApplicationIDs: []string{"app1"}, AllowedScopes: []string{"read"},
			},
			wantSev: riskNone, wantSignals: []string{},
		},
		{
			name: "owner_unset_alone_is_high",
			nhi: model.NonHumanIdentity{
				OwnerUserID: "", ExpiresAt: &soon, LastUsedAt: &recent,
				AllowlistEnforced: true, AllowedApplicationIDs: []string{"app1"}, AllowedScopes: []string{"read"},
			},
			wantSev: riskHigh, wantSignals: []string{"owner_unset"},
		},
		{
			name: "single_signal_long_lived_is_medium",
			nhi: model.NonHumanIdentity{
				OwnerUserID: "alice", ExpiresAt: &farFuture, LastUsedAt: &recent,
				AllowlistEnforced: true, AllowedApplicationIDs: []string{"app1"}, AllowedScopes: []string{"read"},
			},
			wantSev: riskMedium, wantSignals: []string{"no_expiry_long_lived"},
		},
		{
			name: "two_signals_is_high",
			nhi: model.NonHumanIdentity{
				OwnerUserID: "alice", ExpiresAt: &farFuture, LastUsedAt: &stale,
				AllowlistEnforced: true, AllowedApplicationIDs: []string{"app1"}, AllowedScopes: []string{"read"},
			},
			wantSev: riskHigh, wantSignals: []string{"no_expiry_long_lived", "unused"},
		},
		{
			name: "no_expiry_and_wildcard_scope_and_no_owner",
			nhi: model.NonHumanIdentity{
				OwnerUserID: "", ExpiresAt: nil, LastUsedAt: &recent,
				AllowlistEnforced: true, AllowedApplicationIDs: []string{"app1"}, AllowedScopes: []string{"*"},
			},
			wantSev: riskHigh, wantSignals: []string{"owner_unset", "no_expiry_long_lived", "scope_overbroad"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sigs, sev := ComputeRiskSignals(tc.nhi, now)
			if sev != tc.wantSev {
				t.Fatalf("severity = %q, want %q (signals=%v)", sev, tc.wantSev, sigs)
			}
			if len(sigs) != len(tc.wantSignals) {
				t.Fatalf("signals = %v, want %v", sigs, tc.wantSignals)
			}
			got := map[string]bool{}
			for _, s := range sigs {
				got[s] = true
			}
			for _, want := range tc.wantSignals {
				if !got[want] {
					t.Fatalf("missing signal %q in %v", want, sigs)
				}
			}
		})
	}
}

func TestBuildNHIRiskReport(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-1 * time.Hour).Format(time.RFC3339)
	soon := now.Add(24 * time.Hour).Format(time.RFC3339)

	nhis := []model.NonHumanIdentity{
		{ID: "nhi-good", Name: "good", NHIType: "service_account", OwnerUserID: "alice", ExpiresAt: &soon, LastUsedAt: &recent,
			AllowlistEnforced: true, AllowedApplicationIDs: []string{"app1"}, AllowedScopes: []string{"read"}},
		{ID: "nhi-bad", Name: "bad", NHIType: "api_key", OwnerUserID: "", ExpiresAt: nil, LastUsedAt: nil,
			AllowlistEnforced: false},
	}
	rep := BuildRiskReport("tenant-1", nhis, now, now.Format(time.RFC3339))

	if rep.Total != 2 {
		t.Fatalf("total = %d, want 2", rep.Total)
	}
	if rep.TenantID != "tenant-1" || rep.SchemaVersion != "admin_nhi_risk.v1" || !rep.NoSecretAttestation {
		t.Fatalf("bad report header: %+v", rep)
	}
	if rep.BySeverity[riskHigh] != 1 || rep.BySeverity[riskNone] != 1 {
		t.Fatalf("by_severity = %v, want high=1 none=1", rep.BySeverity)
	}
	// Highest severity sorts first.
	if rep.Identities[0].ID != "nhi-bad" || rep.Identities[0].Severity != riskHigh {
		t.Fatalf("expected nhi-bad/high first, got %+v", rep.Identities[0])
	}
}

type fakeNHIStore struct {
	list []model.NonHumanIdentity
}

func (f fakeNHIStore) Upsert(context.Context, model.NonHumanIdentity, string, time.Time) (model.NonHumanIdentity, error) {
	return model.NonHumanIdentity{}, nil
}
func (f fakeNHIStore) List(context.Context, string) ([]model.NonHumanIdentity, error) {
	return f.list, nil
}
func (f fakeNHIStore) CountActive(context.Context, string, time.Time) (int, error) { return 0, nil }
func (f fakeNHIStore) MarkUsed(context.Context, string, string, time.Time) (bool, error) {
	return false, nil
}
func (f fakeNHIStore) ConfigGeneration() uint64 { return 0 }

func TestEnrichDecisionRequestWithNHIRisk(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	store := fakeNHIStore{list: []model.NonHumanIdentity{
		{ID: "nhi-bad", OwnerUserID: "", ExpiresAt: nil, LastUsedAt: nil, AllowlistEnforced: false},
	}}

	req := model.DecisionRequest{TenantID: "t1", ActorNHIID: "nhi-bad"}
	got := EnrichDecisionRequestWithRisk(context.Background(), req, store, now)
	if got.NHIRiskSeverity != riskHigh {
		t.Fatalf("severity = %q, want high", got.NHIRiskSeverity)
	}

	// No actor NHI -> unchanged.
	req2 := model.DecisionRequest{TenantID: "t1"}
	if got2 := EnrichDecisionRequestWithRisk(context.Background(), req2, store, now); got2.NHIRiskSeverity != "" {
		t.Fatalf("expected empty severity for no actor NHI, got %q", got2.NHIRiskSeverity)
	}

	// Unknown NHI -> unchanged.
	req3 := model.DecisionRequest{TenantID: "t1", ActorNHIID: "nhi-missing"}
	if got3 := EnrichDecisionRequestWithRisk(context.Background(), req3, store, now); got3.NHIRiskSeverity != "" {
		t.Fatalf("expected empty severity for unknown NHI, got %q", got3.NHIRiskSeverity)
	}

	// Review #18: a client-supplied severity must never be the gate input. Pre-setting "none" used to skip
	// the recomputation entirely, suppressing every risk-gated policy for the flow.
	req4 := model.DecisionRequest{TenantID: "t1", ActorNHIID: "nhi-bad", NHIRiskSeverity: "none"}
	if got4 := EnrichDecisionRequestWithRisk(context.Background(), req4, store, now); got4.NHIRiskSeverity != riskHigh {
		t.Fatalf("client-supplied severity must be recomputed server-side, got %q", got4.NHIRiskSeverity)
	}
	// And with no actor NHI, a client-claimed severity is cleared, not passed through.
	req5 := model.DecisionRequest{TenantID: "t1", NHIRiskSeverity: "high"}
	if got5 := EnrichDecisionRequestWithRisk(context.Background(), req5, store, now); got5.NHIRiskSeverity != "" {
		t.Fatalf("client-supplied severity with no actor NHI must be cleared, got %q", got5.NHIRiskSeverity)
	}
}
