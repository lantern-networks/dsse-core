package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	assetcatalog "github.com/lantern-networks/dsse-core/assetcatalog"
	policyrule "github.com/lantern-networks/dsse-core/policyrule"
)

// adoptDestinationEndpointID resolves (or creates) an asset-catalog network endpoint for an observed lateral
// flow's destination, returning its endpoint id — so an S2-adopted rule references a FIRST-CLASS, GUI-visible,
// editable destination object instead of a raw IP. This matters twice: (1) a raw IP in a rule's destination is
// not a catalog endpoint, so it does not appear in the Console and the rule cannot be re-edited (the subject
// picker can't reload it); (2) worse, `CompileEastWest`→`DestinationTokens` can't resolve a raw IP to an address,
// yielding an EMPTY selector — which `eastWestSelectorMatches` treats as WILDCARD, silently making a per-host
// adopted rule match ANY destination. Materializing the endpoint fixes both: the rule scopes to exactly the
// observed host and the endpoint shows up under Networks/Assets. Dedups by address (reuse an existing endpoint).
func adoptDestinationEndpointID(ctx context.Context, assets *assetcatalog.Store, tenant, address string) (string, error) {
	address = strings.TrimSpace(address)
	if assets == nil || address == "" {
		return address, nil // best-effort fallback: keep the raw value (still a valid, if unnamed, selector)
	}
	for _, ep := range assets.ListEndpoints(tenant) {
		if ep.Kind == assetcatalog.KindNetwork && strings.EqualFold(strings.TrimSpace(ep.Address), address) {
			return ep.ID, nil // reuse the existing endpoint for this destination
		}
	}
	ep, err := assets.UpsertEndpointContext(ctx, assetcatalog.Endpoint{
		TenantID: tenant,
		Kind:     assetcatalog.KindNetwork,
		Address:  address,
		Alias:    address, // readable default; the operator can rename it in the Console (alias is tenant-unique)
		Source:   assetcatalog.SourceManual,
	})
	if err != nil {
		return "", err
	}
	return ep.ID, nil
}

// adoptServiceIDForObservation resolves the catalog service id an S2-adopted East-West rule should carry for an
// observed lateral flow. It prefers a PORT match against the tenant's services (built-in + authored) because a
// port is unambiguous (22→SSH, 445→SMB, 3389→RDP, 5985→WinRM-HTTP) where a family string is not (winrm maps to two
// services). It falls back to the built-in-svc-<family> convention, then to "" (a destination-only allow rule with
// no service constraint) — every fallback is still a valid allow.
func adoptServiceIDForObservation(assets *assetcatalog.Store, tenant string, port int, family string) string {
	if assets != nil && port > 0 {
		for _, svc := range assets.ListServices(tenant) {
			for _, p := range svc.Ports {
				if strings.EqualFold(strings.TrimSpace(p.Protocol), "tcp") && p.Port == port {
					return svc.ID
				}
			}
		}
	}
	if fam := strings.ToLower(strings.TrimSpace(family)); fam != "" {
		return "builtin-svc-" + fam
	}
	return ""
}

// registerRulesAdmin wires the unified rule-authoring API on the product edge — `source → destination :
// service ⇒ action` across the east-west and egress planes. Model + storage live in dsse-core (so audit
// logs reference the named authored rule); these reuse the admin.policy.* RBAC scope (rules are policy
// authoring). East-west INBOUND rules are validated against their receivers' platforms (resolved from the
// asset catalog) — inbound enforces on Windows WFP only.
func registerRulesAdmin(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, rules *policyrule.Store, assets *assetcatalog.Store, onRulesChanged func(), onRuleDeleted func(tenantID, ruleID string), configSourceURL string, auditMutation func(*http.Request, policyrule.Rule, string, string)) {
	var mutationMu sync.Mutex
	mux.HandleFunc("GET /admin/rules", adminEndpoint("admin.policy.read", func(w http.ResponseWriter, r *http.Request) {
		if !refreshAuthoredStores(w, rules, assets) {
			return
		}
		tenant := adminTenantIDFromRequest(r)
		listed := rules.List(tenant, r.URL.Query().Get("plane"))
		// ★★ A RULE CAN BE "ACTIVE" AND MATCH NOTHING, AND ONLY A LOG SAID SO (2026-08-17, measured as a
		// customer administrator). An egress rule whose destination resolves to zero addresses compiles to a
		// match-nothing sentinel — deliberately, so the rule stays visible rather than vanishing — and the
		// compiler logs "a DENY here is NOT enforcing". Its own comment says "the log is how the operator
		// learns their rule is degraded". It is not: the rules screen showed the rule as ACTIVE / deny, and
		// asking the policy checker about the very host it names answered ALLOW.
		//
		// The route already holds the resolver the compiler uses, so it can answer the same question here.
		out := make([]ruleWithEnforcement, 0, len(listed))
		for _, rule := range listed {
			out = append(out, ruleWithEnforcement{
				Rule:                    rule,
				DestinationUnresolved:   destinationResolvesToNothing(rule, assets, tenant),
				InspectionSourceWarning: policyrule.InspectionSourceWarning(tenant, rule, assets),
			})
		}
		writeJSON(w, http.StatusOK, out)
	}))
	// ★ REFUSED on a config-pulling Edge, and this guard is half of the fix rather than an afterthought.
	// Authored rules became control-plane state on 2026-08-10 so that every Edge holds the same set. Leaving
	// the local write path open would have replaced one silent divergence with a worse one: the admin writes a
	// rule, this Edge accepts it, enforces it, reports it — and the next config-bundle pull (10s) replaces the
	// whole set with the CP's and the rule is gone, with no error anywhere. That is the shape this work exists
	// to remove, so it must not be re-introduced by the same commit.
	mux.HandleFunc("POST /admin/rules", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "authored rules") {
			return
		}
		var rule policyrule.Rule
		if err := decodeLimitedJSONBody(w, r, &rule, maxEdgeRuntimeJSONBodyBytes); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode rule: %w", err))
			return
		}
		tenant := adminTenantIDFromRequest(r)
		rule.TenantID = tenant
		mutationMu.Lock()
		defer mutationMu.Unlock()
		if !refreshAuthoredStores(w, rules, assets) {
			return
		}
		warning, verr := validateInboundReceivers(rule, assets, tenant)
		if verr != nil {
			writeError(w, http.StatusBadRequest, verr)
			return
		}
		stored, err := rules.UpsertContext(r.Context(), rule)
		if auditMutation != nil {
			result := "saved"
			if err != nil {
				result = "rejected"
				if errors.Is(err, policyrule.ErrPersistence) {
					result = "persistence_unconfirmed"
				}
			}
			item := stored
			if err != nil {
				item = rule
			}
			auditMutation(r, item, "upsert", result)
		}
		if err != nil {
			if errors.Is(err, policyrule.ErrPersistence) {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("Saving the rule was not confirmed. The previous live rules remain active. Restore storage, reload and retry."))
			} else {
				writeError(w, http.StatusBadRequest, err)
			}
			return
		}
		// Say it at the moment it is written, too. An administrator who has just typed a hostname into a field
		// that wanted an endpoint should not have to notice a badge on a list later.
		if destinationResolvesToNothing(stored, assets, tenant) {
			if warning != "" {
				warning += " "
			}
			warning += "This rule's destination does not resolve to anything in this organization's endpoints, " +
				"so it matches no traffic and enforces nothing. Add the destination to the endpoint catalog, " +
				"or pick one from it."
		}
		// Recompile enforcement from the authored rules: the egress bypass set + the compiled east-west rule
		// set (both rebuilt from scratch and applied to the live engine / policy store).
		if onRulesChanged != nil {
			onRulesChanged()
		}
		writeJSON(w, http.StatusOK, struct {
			policyrule.Rule
			Warning string `json:"warning,omitempty"`
		}{Rule: stored, Warning: warning})
	}))
	mux.HandleFunc("DELETE /admin/rules/{id}", adminEndpoint("admin.policy.write", func(w http.ResponseWriter, r *http.Request) {
		if configWriteRejectedWhenSourced(w, configSourceURL, "authored rules") {
			return
		}
		tenant := adminTenantIDFromRequest(r)
		id := r.PathValue("id")
		mutationMu.Lock()
		defer mutationMu.Unlock()
		if !refreshAuthoredStores(w, rules, assets) {
			return
		}
		previous, _ := rules.Get(tenant, id)
		previous.TenantID, previous.ID = tenant, id
		ok, err := rules.DeleteContext(r.Context(), tenant, id)
		if auditMutation != nil {
			result := "saved"
			if err != nil {
				result = "persistence_unconfirmed"
			} else if !ok {
				result = "not_found"
			}
			auditMutation(r, previous, "delete", result)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("Saving the rule deletion was not confirmed. The previous live rules remain active. Restore storage, reload and retry."))
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("rule not found"))
			return
		}
		// Reverse-sync a cert-pin bypass rule's lifecycle: deleting the rule un-materializes the pinned-site
		// candidate it came from, so the Pinned Sites view does not linger as "materialized" after the bypass is
		// gone (the bypass itself stops because the rule is its single source). Runs before the recompile.
		if onRuleDeleted != nil {
			onRuleDeleted(tenant, id)
		}
		if onRulesChanged != nil {
			onRulesChanged()
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
	}))
	// Compile enforcement ONCE at startup from whatever rules the store already holds. With a durable
	// -policy-rule-store the store is rehydrated with the operator's authored rules on boot, but the compiled
	// enforcement primitives (east-west rule set + egress allow/deny policies) are only (re)built in
	// onRulesChanged — which otherwise fires solely on a live POST/DELETE. Without this call, persisted rules
	// would RENDER after a restart yet not be ENFORCED until each was re-saved. Compiling here makes authored
	// rules effective across a restart, matching their persistence.
	if onRulesChanged != nil {
		onRulesChanged()
	}
}

// validateInboundReceivers resolves an inbound east-west rule's receiver platforms from the asset catalog
// and applies the macOS-inbound constraint: a save-blocking error for macOS-only receivers, a warning (no
// error) for a mixed set, a no-op otherwise.
func validateInboundReceivers(rule policyrule.Rule, assets *assetcatalog.Store, tenantID string) (string, error) {
	ids := policyrule.InboundReceiversNeedingPlatform(rule)
	if len(ids) == 0 {
		return "", nil
	}
	platforms, macAliases := assets.ResolvePlatforms(tenantID, ids)
	warning, err := policyrule.ValidateInboundReceiverPlatforms(rule, platforms, macAliases)
	if errors.Is(err, policyrule.ErrMacOSInboundUnsupported) {
		return "", err
	}
	return warning, err
}

// ruleWithEnforcement is an authored rule plus the one thing the rule itself cannot say: whether it will
// actually match anything once compiled. See the GET handler for the defect this exists for.
type ruleWithEnforcement struct {
	policyrule.Rule
	// DestinationUnresolved: the destination names nothing this organization's endpoint catalog knows, so the
	// compiled policy is the match-nothing sentinel. The rule is present, active, and enforces nothing.
	DestinationUnresolved   bool   `json:"destination_unresolved,omitempty"`
	InspectionSourceWarning string `json:"inspection_source_warning,omitempty"`
}

// destinationResolvesToNothing asks the compiler's own question with the compiler's own resolver: does this
// rule's destination turn into at least one address for this tenant?
//
// "Any" is not unresolved — it is a deliberate wildcard the compiler handles separately. An empty destination
// is left alone for the same reason: it is the east-west plane's shape, not a broken egress rule.
func destinationResolvesToNothing(rule policyrule.Rule, assets *assetcatalog.Store, tenant string) bool {
	if assets == nil || len(rule.Destination) == 0 || policyrule.IsAnySubject(rule.Destination) {
		return false
	}
	for _, address := range assets.EndpointAddresses(tenant, rule.Destination) {
		if strings.TrimSpace(address) != "" {
			return false
		}
	}
	return true
}

// unresolvedDestinationRuleIDs is destinationResolvesToNothing over a set, for the views that list rules
// alongside everything else the engine merges.
func unresolvedDestinationRuleIDs(rules []policyrule.Rule, assets *assetcatalog.Store, tenant string) map[string]bool {
	out := map[string]bool{}
	for _, rule := range rules {
		if destinationResolvesToNothing(rule, assets, tenant) {
			out[rule.ID] = true
		}
	}
	return out
}
