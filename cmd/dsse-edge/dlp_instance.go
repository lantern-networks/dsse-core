package main

import (
	"strings"

	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/model"
)

// corporateDomainsForTenant builds the CorporateDomains resolver from the tenant's registered end-user IdP
// connections: the union of every connection's VerifiedDomains is the tenant's sanctioned corporate domains
// (the authoritative "our organization" set), reused here to classify a DLP destination instance. Returns nil
// when the store is nil so instance-scoped rules stay inert.
func corporateDomainsForTenant(store *idpregistry.Store) func(tenantID string) []string {
	if store == nil {
		return nil
	}
	return func(tenantID string) []string {
		var domains []string
		seen := map[string]bool{}
		for _, c := range store.List(tenantID) {
			for _, d := range c.VerifiedDomains {
				d = strings.ToLower(strings.TrimSpace(d))
				if d != "" && !seen[d] {
					seen[d] = true
					domains = append(domains, d)
				}
			}
		}
		return domains
	}
}

// Instance-aware DLP action (slice I, the sovereign "here not there"): a DLP rule may be scoped to the
// destination INSTANCE — the corporate (sanctioned) tenant of a SaaS vs a personal/external account. The class
// is derived from the account the SWG egress path already extracts (dec.Metadata ai_email / ai_account, from the
// request's identity token), classified against the tenant's verified corporate domains. Non-secret: only the
// class ("corporate" / "personal" / "") is ever used or recorded, never the account address itself.

// dlpInstanceClass classifies a destination instance from the signed-in account email:
//   - "corporate": the account domain is one of the tenant's verified corporate domains (the sanctioned instance).
//   - "personal":  a confirmed account domain that is NOT one of them (a consumer or other-org account).
//   - "":          no account signal, or no corporate domains configured — cannot classify, so a scoped rule is
//     inert (this deliberately never over-blocks an unclassifiable destination).
func dlpInstanceClass(accountEmail string, corporateDomains []string) string {
	if len(corporateDomains) == 0 {
		return "" // without the sanctioned set we cannot say "corporate" vs not — fail open (scoped rules inert)
	}
	at := strings.LastIndexByte(accountEmail, '@')
	if at < 0 || at == len(accountEmail)-1 {
		return "" // no email → no instance signal
	}
	domain := strings.ToLower(strings.TrimSpace(accountEmail[at+1:]))
	if domain == "" {
		return ""
	}
	for _, d := range corporateDomains {
		if strings.EqualFold(strings.TrimSpace(d), domain) {
			return "corporate"
		}
	}
	return "personal"
}

// dlpInstanceScopeApplies reports whether a DLP rule with the given instance scope applies to a request of the
// given instance class. Empty/"any" scope always applies (back-compat). A corporate/personal scope applies only
// when the class is confidently that; an unknown class ("") matches no scoped rule.
func dlpInstanceScopeApplies(scope, class string) bool {
	scope = strings.TrimSpace(scope)
	if scope == "" || scope == "any" {
		return true
	}
	return scope == class
}

// dlpKnownInstanceScope reports whether an admin-supplied instance scope value is valid.
func dlpKnownInstanceScope(scope string) bool {
	switch strings.TrimSpace(scope) {
	case "", "any", "corporate", "personal":
		return true
	default:
		return false
	}
}

// dlpDecisionAccountEmail returns the signed-in account the SWG egress path stamped on the decision (ai_email
// preferred — a real address; else the ai_account grouping key), used to classify the destination instance.
func dlpDecisionAccountEmail(dec model.AccessDecision) string {
	if dec.Metadata == nil {
		return ""
	}
	if e, ok := dec.Metadata["ai_email"].(string); ok && strings.TrimSpace(e) != "" {
		return e
	}
	if a, ok := dec.Metadata["ai_account"].(string); ok {
		return a
	}
	return ""
}
