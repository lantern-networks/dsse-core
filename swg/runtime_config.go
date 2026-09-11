package swg

import (
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/swghttprewrite"
)

type RuntimeConfigInput struct {
	TenantRestrictionOperatorConfigPath string
	// TenantRestrictionOperatorValueStorePath is the durable operator value store (real.json) that the
	// dataplane preserves across restarts. Admin API writes persist here too so a restart keeps them.
	TenantRestrictionOperatorValueStorePath string
	PolicyBundle                            model.PolicyBundle
	RuntimeTLSDecryptionObserved            bool
	MacCATrustObserved                      bool
}

type RuntimeConfig struct {
	TenantRestrictionOperatorConfigPath     string
	TenantRestrictionOperatorValueStorePath string
	TenantRestrictionResolver               swghttprewrite.OperatorManagedHeaderValueResolver
	TenantRestrictionOperatorConfigRefs     []string
	TenantRestrictionResolverConfigured     bool
	TenantRestrictionHeaderValueLogged      bool
	TenantRestrictionHeaderValueInDecision  bool
	RuntimeTLSDecryptionObserved            bool
	RuntimeHeaderInjectionObserved          bool
	MacCATrustObserved                      bool
	NetworkExtensionRuntimeUsed             bool
	ProductizationClaimsMade                bool
	NewProductClaimsMade                    bool
}

func LoadRuntimeConfig(input RuntimeConfigInput) (RuntimeConfig, error) {
	base := RuntimeConfig{
		TenantRestrictionOperatorValueStorePath: strings.TrimSpace(input.TenantRestrictionOperatorValueStorePath),
		RuntimeTLSDecryptionObserved:            input.RuntimeTLSDecryptionObserved,
		MacCATrustObserved:                      input.MacCATrustObserved,
	}
	path := strings.TrimSpace(input.TenantRestrictionOperatorConfigPath)
	if path == "" {
		if PolicyBundleHasActiveTenantRestrictionRules(input.PolicyBundle) {
			return RuntimeConfig{}, fmt.Errorf("swg tenant restriction operator config is required when active tenant restriction rules are configured")
		}
		return base, nil
	}

	resolver, err := swghttprewrite.LoadOperatorManagedHeaderValueResolver(path, input.PolicyBundle)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("load swg tenant restriction operator config: %w", err)
	}

	base.TenantRestrictionOperatorConfigPath = path
	base.TenantRestrictionResolver = resolver
	base.TenantRestrictionOperatorConfigRefs = resolver.OperatorConfigRefs()
	base.TenantRestrictionResolverConfigured = true
	return base, nil
}

func PolicyBundleHasActiveTenantRestrictionRules(bundle model.PolicyBundle) bool {
	for _, rule := range bundle.SWGTenantRestrictionRules {
		status := strings.ToLower(strings.TrimSpace(rule.Status))
		if status == "" || status == "active" {
			return true
		}
	}
	return false
}
