package main

import (
	"strings"

	"github.com/lantern-networks/dsse-core/idpregistry"
)

// corporateDomainsForTenant builds the CorporateDomains resolver from the tenant's registered end-user IdP
// connections: the union of every connection's VerifiedDomains is the tenant's sanctioned corporate domains
// (the authoritative "our organization" set), reused here to classify a DLP destination instance. Returns nil
// when the store is nil. Domains alone do not verify a destination account.
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
// requires independently verified destination-account evidence before it can exclude a scoped rule. The
// ai_email / ai_account request hints are not such evidence. Unknown accounts retain scoped inspection.

// dlpInstanceClass compares an independently verified account email with the tenant's domains. It does not
// authenticate that email, and must not be called with request JWT/cookie hints to make a policy exemption:
//   - "corporate": the account domain is one of the tenant's verified corporate domains (the sanctioned instance).
//   - "personal":  a confirmed account domain that is NOT one of them (a consumer or other-org account).
//   - "":          no account signal, or no corporate domains configured — cannot classify.
func dlpInstanceClass(accountEmail string, corporateDomains []string) string {
	if len(corporateDomains) == 0 {
		return "" // unknown does not exempt the request from scoped inspection
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
// when the class is confidently that. Unknown or unrecognized classes apply both corporate and personal
// scopes: absence of verified account evidence must not disable an administrator's DLP rule.
func dlpInstanceScopeApplies(scope, class string) bool {
	scope = strings.TrimSpace(scope)
	if scope == "" || scope == "any" {
		return true
	}
	if scope != "corporate" && scope != "personal" {
		return false
	}
	if class != "corporate" && class != "personal" {
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
