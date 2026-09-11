package policycache

import (
	"fmt"
	"time"
)

const (
	ControlPlaneReachable    = "control_plane_reachable"
	ControlPlaneUnreachable  = "control_plane_unreachable"
	ControlPlaneNotReported  = "not_reported"
	PolicySourceRemote       = "remote"
	PolicySourceCache        = "last_verified_signed_policy_bundle"
	PolicySourceMissing      = "missing_verified_policy_bundle"
	DecisionScopeContinue    = "protected_traffic_decision_continues_metadata_only"
	DecisionScopeNoDegraded  = "no_degraded_decision"
	HealthHealthy            = "healthy"
	HealthDegraded           = "degraded"
	HealthFailSecure         = "fail_secure"
	FailureNone              = "none"
	FailureMissingBundle     = "missing_verified_policy_bundle"
	FailureExpiredBundle     = "expired_verified_policy_bundle"
	FailureUnverifiedBundle  = "unverified_policy_bundle"
	FailureInvalidStatus     = "invalid_policy_bundle_status"
	RawMaterialNotIncluded   = false
	DefaultMaxCacheStaleness = 24 * time.Hour
)

type Snapshot struct {
	ControlPlaneReachability string
	VerifiedSignedBundle     bool
	PolicyBundleStatus       string
	PolicyBundleIDPresent    bool
	PolicyBundleVersion      string
	VerifiedAt               time.Time
	ExpiresAt                time.Time
	Now                      time.Time
}

type Evaluation struct {
	PolicyCacheHealth                       string
	ControlPlaneReachabilityCategory        string
	DegradedOperationPolicySourceCategory   string
	DegradedOperationDecisionScopeCategory  string
	FailSecureGate                          string
	PolicyApplyResult                       string
	PolicyApplyFailureCategory              string
	LastVerifiedSignedPolicyBundleAvailable bool
	RawPolicyBundleIncluded                 bool
	RawEndpointValuesIncluded               bool
	RawHostValuesIncluded                   bool
	RawNetworkValuesIncluded                bool
	CredentialsIncluded                     bool
	AuthMaterialIncluded                    bool
}

type Contract struct {
	MaxCacheStaleness time.Duration
}

func DefaultContract() Contract {
	return Contract{MaxCacheStaleness: DefaultMaxCacheStaleness}
}

func (contract Contract) Evaluate(snapshot Snapshot) (Evaluation, error) {
	if contract.MaxCacheStaleness <= 0 {
		return Evaluation{}, fmt.Errorf("max cache staleness must be positive")
	}
	now := snapshot.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	reachability := normalizeReachability(snapshot.ControlPlaneReachability)
	if !snapshot.VerifiedSignedBundle {
		return failSecureEvaluation(reachability, FailureUnverifiedBundle), nil
	}
	if !snapshot.PolicyBundleIDPresent || snapshot.PolicyBundleVersion == "" {
		return failSecureEvaluation(reachability, FailureMissingBundle), nil
	}
	if snapshot.PolicyBundleStatus != "active" {
		return failSecureEvaluation(reachability, FailureInvalidStatus), nil
	}
	if snapshot.VerifiedAt.IsZero() || now.Sub(snapshot.VerifiedAt) > contract.MaxCacheStaleness {
		return failSecureEvaluation(reachability, FailureExpiredBundle), nil
	}
	if !snapshot.ExpiresAt.IsZero() && now.After(snapshot.ExpiresAt) {
		return failSecureEvaluation(reachability, FailureExpiredBundle), nil
	}
	if reachability == ControlPlaneUnreachable {
		return Evaluation{
			PolicyCacheHealth:                       HealthDegraded,
			ControlPlaneReachabilityCategory:        reachability,
			DegradedOperationPolicySourceCategory:   PolicySourceCache,
			DegradedOperationDecisionScopeCategory:  DecisionScopeContinue,
			FailSecureGate:                          "not_triggered",
			PolicyApplyResult:                       "cache_fallback",
			PolicyApplyFailureCategory:              FailureNone,
			LastVerifiedSignedPolicyBundleAvailable: true,
			RawPolicyBundleIncluded:                 RawMaterialNotIncluded,
			RawEndpointValuesIncluded:               RawMaterialNotIncluded,
			RawHostValuesIncluded:                   RawMaterialNotIncluded,
			RawNetworkValuesIncluded:                RawMaterialNotIncluded,
			CredentialsIncluded:                     RawMaterialNotIncluded,
			AuthMaterialIncluded:                    RawMaterialNotIncluded,
		}, nil
	}
	return Evaluation{
		PolicyCacheHealth:                       HealthHealthy,
		ControlPlaneReachabilityCategory:        reachability,
		DegradedOperationPolicySourceCategory:   PolicySourceRemote,
		DegradedOperationDecisionScopeCategory:  DecisionScopeNoDegraded,
		FailSecureGate:                          "not_triggered",
		PolicyApplyResult:                       "applied",
		PolicyApplyFailureCategory:              FailureNone,
		LastVerifiedSignedPolicyBundleAvailable: true,
		RawPolicyBundleIncluded:                 RawMaterialNotIncluded,
		RawEndpointValuesIncluded:               RawMaterialNotIncluded,
		RawHostValuesIncluded:                   RawMaterialNotIncluded,
		RawNetworkValuesIncluded:                RawMaterialNotIncluded,
		CredentialsIncluded:                     RawMaterialNotIncluded,
		AuthMaterialIncluded:                    RawMaterialNotIncluded,
	}, nil
}

func normalizeReachability(value string) string {
	switch value {
	case ControlPlaneReachable, ControlPlaneUnreachable:
		return value
	default:
		return ControlPlaneNotReported
	}
}

func failSecureEvaluation(reachability, failure string) Evaluation {
	return Evaluation{
		PolicyCacheHealth:                       HealthFailSecure,
		ControlPlaneReachabilityCategory:        reachability,
		DegradedOperationPolicySourceCategory:   PolicySourceMissing,
		DegradedOperationDecisionScopeCategory:  DecisionScopeNoDegraded,
		FailSecureGate:                          "triggered",
		PolicyApplyResult:                       "failed",
		PolicyApplyFailureCategory:              failure,
		LastVerifiedSignedPolicyBundleAvailable: false,
		RawPolicyBundleIncluded:                 RawMaterialNotIncluded,
		RawEndpointValuesIncluded:               RawMaterialNotIncluded,
		RawHostValuesIncluded:                   RawMaterialNotIncluded,
		RawNetworkValuesIncluded:                RawMaterialNotIncluded,
		CredentialsIncluded:                     RawMaterialNotIncluded,
		AuthMaterialIncluded:                    RawMaterialNotIncluded,
	}
}
