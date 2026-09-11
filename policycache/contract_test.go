package policycache

import (
	"testing"
	"time"
)

func TestEvaluateUsesLastVerifiedBundleWhenControlPlaneUnreachable(t *testing.T) {
	now := time.Date(2026, 6, 10, 2, 10, 0, 0, time.UTC)
	evaluation, err := DefaultContract().Evaluate(Snapshot{
		ControlPlaneReachability: ControlPlaneUnreachable,
		VerifiedSignedBundle:     true,
		PolicyBundleStatus:       "active",
		PolicyBundleIDPresent:    true,
		PolicyBundleVersion:      "2026.06.10.001",
		VerifiedAt:               now.Add(-time.Hour),
		ExpiresAt:                now.Add(time.Hour),
		Now:                      now,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if evaluation.PolicyCacheHealth != HealthDegraded {
		t.Fatalf("PolicyCacheHealth = %q, want degraded", evaluation.PolicyCacheHealth)
	}
	if evaluation.DegradedOperationPolicySourceCategory != PolicySourceCache {
		t.Fatalf("policy source = %q, want last verified cache", evaluation.DegradedOperationPolicySourceCategory)
	}
	if evaluation.DegradedOperationDecisionScopeCategory != DecisionScopeContinue {
		t.Fatalf("decision scope = %q, want protected traffic continues", evaluation.DegradedOperationDecisionScopeCategory)
	}
	if evaluation.PolicyApplyResult != "cache_fallback" || evaluation.FailSecureGate != "not_triggered" {
		t.Fatalf("evaluation = %+v, want cache fallback without fail-secure", evaluation)
	}
	assertNoRawMaterial(t, evaluation)
}

func TestEvaluateHealthyWhenControlPlaneReachableAndBundleVerified(t *testing.T) {
	now := time.Date(2026, 6, 10, 2, 15, 0, 0, time.UTC)
	evaluation, err := DefaultContract().Evaluate(Snapshot{
		ControlPlaneReachability: ControlPlaneReachable,
		VerifiedSignedBundle:     true,
		PolicyBundleStatus:       "active",
		PolicyBundleIDPresent:    true,
		PolicyBundleVersion:      "2026.06.10.001",
		VerifiedAt:               now.Add(-time.Minute),
		ExpiresAt:                now.Add(time.Hour),
		Now:                      now,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if evaluation.PolicyCacheHealth != HealthHealthy {
		t.Fatalf("PolicyCacheHealth = %q, want healthy", evaluation.PolicyCacheHealth)
	}
	if evaluation.DegradedOperationPolicySourceCategory != PolicySourceRemote {
		t.Fatalf("policy source = %q, want remote", evaluation.DegradedOperationPolicySourceCategory)
	}
	if evaluation.DegradedOperationDecisionScopeCategory != DecisionScopeNoDegraded {
		t.Fatalf("decision scope = %q, want no degraded decision", evaluation.DegradedOperationDecisionScopeCategory)
	}
	assertNoRawMaterial(t, evaluation)
}

func TestEvaluateFailSecureWhenVerifiedBundleExpired(t *testing.T) {
	now := time.Date(2026, 6, 10, 2, 20, 0, 0, time.UTC)
	evaluation, err := DefaultContract().Evaluate(Snapshot{
		ControlPlaneReachability: ControlPlaneUnreachable,
		VerifiedSignedBundle:     true,
		PolicyBundleStatus:       "active",
		PolicyBundleIDPresent:    true,
		PolicyBundleVersion:      "2026.06.10.001",
		VerifiedAt:               now.Add(-time.Hour),
		ExpiresAt:                now.Add(-time.Second),
		Now:                      now,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if evaluation.PolicyCacheHealth != HealthFailSecure {
		t.Fatalf("PolicyCacheHealth = %q, want fail_secure", evaluation.PolicyCacheHealth)
	}
	if evaluation.FailSecureGate != "triggered" || evaluation.PolicyApplyFailureCategory != FailureExpiredBundle {
		t.Fatalf("evaluation = %+v, want expired fail-secure", evaluation)
	}
	if evaluation.DegradedOperationDecisionScopeCategory != DecisionScopeNoDegraded {
		t.Fatalf("decision scope = %q, want no degraded decision", evaluation.DegradedOperationDecisionScopeCategory)
	}
	assertNoRawMaterial(t, evaluation)
}

func TestEvaluateFailSecureWhenBundleMissingOrUnverified(t *testing.T) {
	now := time.Date(2026, 6, 10, 2, 25, 0, 0, time.UTC)
	tests := []struct {
		name     string
		snapshot Snapshot
		failure  string
	}{
		{
			name: "unverified",
			snapshot: Snapshot{
				ControlPlaneReachability: ControlPlaneUnreachable,
				VerifiedSignedBundle:     false,
				PolicyBundleStatus:       "active",
				PolicyBundleIDPresent:    true,
				PolicyBundleVersion:      "2026.06.10.001",
				VerifiedAt:               now,
				ExpiresAt:                now.Add(time.Hour),
				Now:                      now,
			},
			failure: FailureUnverifiedBundle,
		},
		{
			name: "missing_id",
			snapshot: Snapshot{
				ControlPlaneReachability: ControlPlaneUnreachable,
				VerifiedSignedBundle:     true,
				PolicyBundleStatus:       "active",
				PolicyBundleIDPresent:    false,
				PolicyBundleVersion:      "2026.06.10.001",
				VerifiedAt:               now,
				ExpiresAt:                now.Add(time.Hour),
				Now:                      now,
			},
			failure: FailureMissingBundle,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluation, err := DefaultContract().Evaluate(tt.snapshot)
			if err != nil {
				t.Fatalf("Evaluate returned error: %v", err)
			}
			if evaluation.PolicyCacheHealth != HealthFailSecure {
				t.Fatalf("PolicyCacheHealth = %q, want fail_secure", evaluation.PolicyCacheHealth)
			}
			if evaluation.PolicyApplyFailureCategory != tt.failure {
				t.Fatalf("failure = %q, want %q", evaluation.PolicyApplyFailureCategory, tt.failure)
			}
			assertNoRawMaterial(t, evaluation)
		})
	}
}

func TestEvaluateRejectsInvalidContractStaleness(t *testing.T) {
	_, err := (Contract{}).Evaluate(Snapshot{})
	if err == nil {
		t.Fatal("Evaluate returned nil error for zero staleness")
	}
}

func assertNoRawMaterial(t *testing.T, evaluation Evaluation) {
	t.Helper()
	if evaluation.RawPolicyBundleIncluded ||
		evaluation.RawEndpointValuesIncluded ||
		evaluation.RawHostValuesIncluded ||
		evaluation.RawNetworkValuesIncluded ||
		evaluation.CredentialsIncluded ||
		evaluation.AuthMaterialIncluded {
		t.Fatalf("evaluation includes raw/secret material: %+v", evaluation)
	}
}
