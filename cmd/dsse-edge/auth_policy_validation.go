package main

import (
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/oidcbroker"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// A redirected HTTP request is no longer the request that triggered the
// ceremony. Request-bound authentication can therefore release only a held
// native flow. Require an explicit native service selector before activation;
// a port, hostname or protocol alone cannot prove that Web is excluded.
func validateRequestBoundPolicyTransport(policy model.Policy) error {
	if policy.Action.Decision != "require_reauthentication" || policy.Status == "disabled" || policy.Status == "draft" {
		return nil
	}
	req := authFlowRequirements(model.AccessDecision{Actions: []model.DecisionAction{{Type: "prompt_reauthentication", Metadata: policy.Metadata}}}, "validation.invalid:443")
	if req.MaxAgeSeconds == nil || *req.MaxAgeSeconds != 0 {
		return nil
	}
	family, ok := policy.Conditions["service_family"].(string)
	if ok {
		switch strings.ToLower(strings.TrimSpace(family)) {
		case "ssh", "rdp", "smb":
			return nil
		}
	}
	return fmt.Errorf("max_age_seconds=0 requires a held native flow: restrict service_family to ssh, rdp or smb; Web HTTP/HTTPS cannot release the redirected request once")
}

// Saving explicit assurance requirements must use the same provider capability
// checks as starting authentication. Drafts may be stored, but cannot be enabled
// with an unsupported requirement. This does not claim that a remote IdP tenant
// has assigned a Conditional Access policy; that requires its integration test.
func validateAuthPolicyRequirements(registry *idpregistry.Store, tenant string, metadata map[string]any) error {
	if len(metadata) == 0 {
		return nil
	}
	req := authFlowRequirements(model.AccessDecision{Actions: []model.DecisionAction{{Type: "prompt_reauthentication", Metadata: metadata}}}, "validation.invalid:443")
	if req.Invalid {
		return fmt.Errorf("invalid authentication requirements")
	}
	if req.IdP == "" && req.ACR == "" && len(req.AMR) == 0 && req.MaxAgeSeconds == nil {
		return nil
	}
	if registry == nil {
		return fmt.Errorf("configure the authentication provider before activating this policy")
	}
	provider, ok := registry.Resolve(tenant, req.IdP)
	if !ok {
		return fmt.Errorf("authentication provider is unavailable for this policy")
	}
	return oidcbroker.ValidateAuthorizeParams(provider, oidcbroker.AuthorizeParams{ACRValues: req.ACR, RequiredAMR: req.AMR, MaxAgeSeconds: req.MaxAgeSeconds})
}
func validateAuthoredRuleProvider(rule policyrule.Rule, registry *idpregistry.Store) error {
	if strings.ToLower(strings.TrimSpace(rule.Action.Access)) != policyrule.AccessAuthenticate || strings.ToLower(strings.TrimSpace(rule.Status)) == policyrule.StatusDisabled {
		return nil
	}
	if rule.Action.MaxAgeSeconds != nil && *rule.Action.MaxAgeSeconds == 0 {
		// The authored egress model names transport/ports, not a proven native
		// service family; it cannot exclude redirected Web requests. Inbound
		// rules are applied by receiver WFP and cannot hold a browser ceremony.
		if strings.ToLower(strings.TrimSpace(rule.Plane)) != policyrule.PlaneEastWest || strings.EqualFold(strings.TrimSpace(rule.Direction), policyrule.DirectionInbound) {
			return fmt.Errorf("max_age_seconds=0 requires an outbound Connector Access rule; Internet Access and inbound rules cannot release a redirected request once")
		}
	}
	meta := map[string]any{"required_idp_id": rule.Action.RequiredIdPID, "min_acr": rule.Action.MinACR}
	if len(rule.Action.RequiredAMR) > 0 {
		meta["required_amr"] = rule.Action.RequiredAMR
	}
	if rule.Action.MaxAgeSeconds != nil {
		meta["max_age_seconds"] = *rule.Action.MaxAgeSeconds
	}
	return validateAuthPolicyRequirements(registry, rule.TenantID, meta)
}
