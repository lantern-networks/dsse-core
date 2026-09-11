package nhi

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// NHI risk signals. Derive risk signals from the NHI
// inventory — long-lived token / owner unset / over-broad scope / unused — classify a severity, and
// feed it into the decision path (nhi_risk_severity policy condition) so a high-risk Non-Human
// Identity's access can be reduced (NHI zero-trust). Behavioral signals (abnormal time /
// destination) need usage history. Non-secret: enums only.
//
// References: NIST SP 800-207A, OWASP Non-Human Identities Top 10.

const (
	riskNone   = "none"
	riskMedium = "medium"
	riskHigh   = "high"

	longLivedThreshold = 90 * 24 * time.Hour
	unusedThreshold    = 30 * 24 * time.Hour
)

// ComputeRiskSignals returns the detected risk signals (non-secret enums) and the severity.
// owner_unset alone is high (an ownerless NHI is unaccountable); otherwise >=2 signals = high,
// 1 = medium, 0 = none.
func ComputeRiskSignals(nhi model.NonHumanIdentity, now time.Time) ([]string, string) {
	sigs := []string{}

	ownerUnset := strings.TrimSpace(nhi.OwnerUserID) == ""
	if ownerUnset {
		sigs = append(sigs, "owner_unset")
	}

	// Long-lived / no-expiry credential.
	longLived := false
	if nhi.ExpiresAt == nil || strings.TrimSpace(*nhi.ExpiresAt) == "" {
		longLived = true
	} else if t, err := time.Parse(time.RFC3339, strings.TrimSpace(*nhi.ExpiresAt)); err == nil && t.After(now.Add(longLivedThreshold)) {
		longLived = true
	}
	if longLived {
		sigs = append(sigs, "no_expiry_long_lived")
	}

	// Over-broad scope: no allowlist enforcement, no allowed apps (= any), or a wildcard scope.
	overbroad := !nhi.AllowlistEnforced || len(nhi.AllowedApplicationIDs) == 0
	for _, s := range nhi.AllowedScopes {
		if strings.TrimSpace(s) == "*" {
			overbroad = true
		}
	}
	if overbroad {
		sigs = append(sigs, "scope_overbroad")
	}

	// Unused (never used, or not used within the threshold).
	unused := false
	if nhi.LastUsedAt == nil || strings.TrimSpace(*nhi.LastUsedAt) == "" {
		unused = true
	} else if t, err := time.Parse(time.RFC3339, strings.TrimSpace(*nhi.LastUsedAt)); err == nil && t.Before(now.Add(-unusedThreshold)) {
		unused = true
	}
	if unused {
		sigs = append(sigs, "unused")
	}

	severity := riskNone
	switch {
	case ownerUnset || len(sigs) >= 2:
		severity = riskHigh
	case len(sigs) == 1:
		severity = riskMedium
	}
	return sigs, severity
}

type RiskRow struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	NHIType  string   `json:"nhi_type"`
	Severity string   `json:"severity"`
	Signals  []string `json:"signals"`
}

type RiskReport struct {
	SchemaVersion       string         `json:"schema_version"`
	TenantID            string         `json:"tenant_id"`
	GeneratedAt         string         `json:"generated_at"`
	Total               int            `json:"total"`
	BySeverity          map[string]int `json:"by_severity"`
	Identities          []RiskRow      `json:"identities"`
	NoSecretAttestation bool           `json:"no_secret_attestation"`
}

// BuildRiskReport computes risk for every NHI in the inventory. Pure over the supplied list.
func BuildRiskReport(tenantID string, nhis []model.NonHumanIdentity, now time.Time, generatedAt string) RiskReport {
	rows := make([]RiskRow, 0, len(nhis))
	bySev := map[string]int{}
	for _, nhi := range nhis {
		sigs, sev := ComputeRiskSignals(nhi, now)
		rows = append(rows, RiskRow{ID: nhi.ID, Name: nhi.Name, NHIType: nhi.NHIType, Severity: sev, Signals: sigs})
		bySev[sev]++
	}
	sort.Slice(rows, func(i, j int) bool {
		ri, rj := severityRank(rows[i].Severity), severityRank(rows[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return rows[i].ID < rows[j].ID
	})
	return RiskReport{
		SchemaVersion: "admin_nhi_risk.v1", TenantID: tenantID, GeneratedAt: generatedAt,
		Total: len(nhis), BySeverity: bySev, Identities: rows, NoSecretAttestation: true,
	}
}

func severityRank(s string) int {
	switch s {
	case riskHigh:
		return 2
	case riskMedium:
		return 1
	}
	return 0
}

// EnrichDecisionRequestWithRisk sets req.NHIRiskSeverity from the Actor NHI's computed risk so a
// policy can gate on nhi_risk_severity (reduce a high-risk NHI's access). The severity is ALWAYS
// derived server-side: any value already on the request is discarded first — it arrives from the
// client, and honoring it let a caller pre-set nhi_risk_severity ("none") to suppress the
// recomputation and neuter every risk-gated policy for its flow. Empty when the flow has no Actor
// NHI or the NHI is unknown.
func EnrichDecisionRequestWithRisk(ctx context.Context, req model.DecisionRequest, store RuntimeStore, now time.Time) model.DecisionRequest {
	req.NHIRiskSeverity = ""
	if store == nil || strings.TrimSpace(req.ActorNHIID) == "" {
		return req
	}
	list, err := store.List(ctx, req.TenantID)
	if err != nil {
		return req
	}
	for _, nhi := range list {
		if nhi.ID == req.ActorNHIID {
			_, sev := ComputeRiskSignals(nhi, now)
			req.NHIRiskSeverity = sev
			break
		}
	}
	return req
}
