package decision

import (
	"net"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

func (e Evaluator) decisionRequestWithSaaSContext(req model.DecisionRequest) model.DecisionRequest {
	req = clearDecisionRequestSaaSContext(req)
	ctx, ok := SaaSContextForRequest(e.PolicyBundle, req)
	if !ok {
		return req
	}
	req.SaaSApplicationID = ctx.SaaSApplicationID
	req.SaaSName = ctx.Name
	req.SaaSProvider = ctx.Provider
	req.SaaSCategory = ctx.Category
	req.SaaSRiskTier = ctx.RiskTier
	req.SaaSMatchedDomain = ctx.MatchedDomain
	req.SaaSMatchedPattern = ctx.MatchedPattern
	req.SaaSMatchType = ctx.MatchType
	return req
}

func clearDecisionRequestSaaSContext(req model.DecisionRequest) model.DecisionRequest {
	req.SaaSApplicationID = ""
	req.SaaSName = ""
	req.SaaSProvider = ""
	req.SaaSCategory = ""
	req.SaaSRiskTier = ""
	req.SaaSMatchedDomain = ""
	req.SaaSMatchedPattern = ""
	req.SaaSMatchType = ""
	return req
}

func SaaSContextForRequest(bundle model.PolicyBundle, req model.DecisionRequest) (model.SaaSContext, bool) {
	if strings.TrimSpace(req.TenantID) != "" {
		bundle.TenantID = req.TenantID
	}
	candidates := saasCatalogCandidates(req)
	if len(candidates) == 0 {
		return model.SaaSContext{}, false
	}
	for _, entry := range bundle.SaaSCatalog {
		if !saasCatalogEntryInTenantScope(bundle, entry) {
			continue
		}
		for _, candidate := range candidates {
			if pattern, matchType, ok := matchSaaSCatalogPatterns(candidate.Value, candidate.Source, entry); ok {
				return model.SaaSContext{
					SaaSApplicationID: strings.TrimSpace(entry.SaaSApplicationID),
					Name:              strings.TrimSpace(entry.Name),
					Provider:          strings.TrimSpace(entry.Provider),
					Category:          strings.TrimSpace(entry.Category),
					RiskTier:          strings.TrimSpace(entry.RiskTier),
					MatchedDomain:     candidate.Value,
					MatchedPattern:    pattern,
					MatchType:         matchType,
				}, true
			}
		}
	}
	return model.SaaSContext{}, false
}

type saasCatalogCandidate struct {
	Source string
	Value  string
}

func saasCatalogCandidates(req model.DecisionRequest) []saasCatalogCandidate {
	candidates := []saasCatalogCandidate{}
	for _, candidate := range []saasCatalogCandidate{
		{Source: "fqdn", Value: normalizeSaaSDomain(req.FQDN)},
		{Source: "sni", Value: normalizeSaaSDomain(req.SNI)},
		{Source: "destination", Value: normalizeSaaSDomain(req.Destination)},
	} {
		if candidate.Value == "" {
			continue
		}
		if !containsSaaSCatalogCandidate(candidates, candidate.Value, candidate.Source) {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func containsSaaSCatalogCandidate(candidates []saasCatalogCandidate, value, source string) bool {
	for _, candidate := range candidates {
		if candidate.Value == value && candidate.Source == source {
			return true
		}
	}
	return false
}

func saasCatalogEntryInTenantScope(bundle model.PolicyBundle, entry model.SaaSCatalogEntry) bool {
	entryTenantID := strings.TrimSpace(entry.TenantID)
	if entryTenantID == "" {
		return true
	}
	return strings.TrimSpace(bundle.TenantID) == "" || entryTenantID == strings.TrimSpace(bundle.TenantID)
}

func matchSaaSCatalogPatterns(domain, source string, entry model.SaaSCatalogEntry) (string, string, bool) {
	if strings.TrimSpace(entry.SaaSApplicationID) == "" {
		return "", "", false
	}
	for _, pattern := range entry.DomainPatterns {
		if normalized, kind, ok := saasDomainPatternMatches(domain, pattern); ok {
			return normalized, source + "_" + kind, true
		}
	}
	if source != "sni" {
		return "", "", false
	}
	for _, pattern := range entry.SNIPatterns {
		if normalized, kind, ok := saasDomainPatternMatches(domain, pattern); ok {
			return normalized, "sni_" + kind, true
		}
	}
	return "", "", false
}

func saasDomainPatternMatches(domain, pattern string) (string, string, bool) {
	domain = normalizeSaaSDomain(domain)
	pattern = normalizeSaaSDomain(pattern)
	if domain == "" || pattern == "" || pattern == "*" {
		return "", "", false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		if suffix == "" || domain == suffix {
			return "", "", false
		}
		if strings.HasSuffix(domain, "."+suffix) {
			return pattern, "wildcard", true
		}
		return "", "", false
	}
	if domain == pattern {
		return pattern, "exact", true
	}
	return "", "", false
}

func normalizeSaaSDomain(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		parts := strings.SplitN(value, "://", 2)
		value = parts[1]
		if slash := strings.Index(value, "/"); slash >= 0 {
			value = value[:slash]
		}
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.TrimSuffix(value, ".")
	value = strings.TrimSpace(value)
	return value
}
