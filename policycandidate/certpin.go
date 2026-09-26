package policycandidate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// certPinAttribution derives a cert-pin candidate's confidence + suggested admin action from its non-secret
// evidence. An UNATTRIBUTED candidate — identified only by a raw IP literal with no SNI — is "low" confidence and
// "investigate_only": it must never be surfaced as a strong active-bypass approval target (you cannot tell what
// site/app a bare IPv6/CDN address is). A hostname or SNI gives a named entity, so the candidate is "review"-able
// at "medium" confidence. Advisory only — it gates nothing by itself (materialize is the bypass gate).
const suggestedActionInvestigateOnly = "investigate_only"

// attributionSourceDNSTunnel marks a candidate whose FQDN was recovered by correlating the flow's
// connect-by-IP destination against a DNS-over-tunnel answer. Per the design's "evidence sources by trust",
// DNS-over-tunnel correlation is the highest-trust attribution — higher than a TLS SNI — because it ties the
// resolved name to the exact destination IP within the answer's TTL, and it survives ECH.
const attributionSourceDNSTunnel = "dns_tunnel_correlation"

func certPinAttribution(host, sni, attributionSource string) (confidence, suggestedAction string) {
	_, highRisk, err := CertPinBypassTarget(Candidate{Host: host, SNI: sni})
	if err != nil || highRisk {
		return "low", suggestedActionInvestigateOnly
	}
	if strings.TrimSpace(attributionSource) == attributionSourceDNSTunnel {
		return "high", "review"
	}
	return "medium", "review"
}

func normalizeHostValue(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// CertPinCandidateID derives a stable candidate id from the observation key (host/sni/port/reason) so
// repeated detections upsert the same candidate (incrementing failure_count) rather than duplicating.
func CertPinCandidateID(host, sni string, port int, reason string) string {
	key := normalizeHostValue(host) + "|" + normalizeHostValue(sni) + "|" + strconv.Itoa(port) + "|" + strings.TrimSpace(reason)
	sum := sha256.Sum256([]byte(key))
	return "certpin-" + hex.EncodeToString(sum[:10])
}

// ObserveCertPinFailure records a cert-pinning detection: it creates a pending bypass candidate the
// first time, and increments failure_count + refreshes last_observed on subsequent observations. It
// NEVER bypasses — an admin must approve and materialize. An already-decided candidate
// (approved/materialized/rejected/suppressed) keeps its status while still counting observations.
func (store *Store) ObserveCertPinFailure(ctx context.Context, tenantID, host, sni string, port int, reason string, now time.Time) (Candidate, error) {
	return store.observeCertPin(ctx, tenantID, host, sni, "", "", port, reason, now)
}

// ObserveCertPinFailureDNSCorrelated records a cert-pin detection for a connect-by-IP flow (no SNI) whose real
// FQDN was recovered from the DNS-over-tunnel conntrack. The candidate is keyed by the recovered ENTITY (the
// FQDN, not the raw IP) so detections to the same name dedup, it carries "high" confidence (DNS correlation is
// the strongest attribution evidence), and the originating IP is retained as evidence. This is how a raw-IPv6/
// CDN candidate that would otherwise be investigate_only becomes a normal, named admin review item.
func (store *Store) ObserveCertPinFailureDNSCorrelated(ctx context.Context, tenantID, fqdn, observedIP string, port int, reason string, now time.Time) (Candidate, error) {
	return store.observeCertPin(ctx, tenantID, fqdn, "", observedIP, attributionSourceDNSTunnel, port, reason, now)
}

func (store *Store) observeCertPin(ctx context.Context, tenantID, host, sni, observedIP, attributionSource string, port int, reason string, now time.Time) (Candidate, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Candidate{}, fmt.Errorf("tenant_id is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	observed := now.UTC().Format(time.RFC3339)
	id := CertPinCandidateID(host, sni, port, reason)

	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.persister.(candidateSharedPersister); ok {
		return sharedCandidateMutation(store, ctx, func(next *Store) (Candidate, error) {
			return next.observeCertPin(ctx, tenantID, host, sni, observedIP, attributionSource, port, reason, now)
		})
	}

	existing, found := store.candidates[tenantID][id]
	cand := certPinCandidate(existing, found, id, tenantID, host, sni, observedIP, attributionSource, port, reason, observed, 1)
	normalized, err := normalizeObservation(cand, tenantID, now)
	if err != nil {
		return Candidate{}, err
	}
	if err := store.putLocked(normalized); err != nil {
		return Candidate{}, err
	}
	return copyCandidate(normalized), nil
}

// certPinCandidate is the candidate after times more cert-pinning detections.
func certPinCandidate(existing Candidate, found bool, id, tenantID, host, sni, observedIP, attributionSource string, port int, reason, observed string, times int) Candidate {
	cand := Candidate{
		CandidateID:       id,
		TenantID:          tenantID,
		Source:            SourceCertPinningDetection,
		CandidateType:     "bypass_policy",
		ProposedAction:    "bypass",
		Host:              host,
		SNI:               sni,
		Port:              port,
		ServiceFamily:     "https",
		ReasonCodes:       []string{strings.TrimSpace(reason)},
		FailureCount:      times,
		LastObserved:      &observed,
		ObservedIP:        strings.TrimSpace(observedIP),
		AttributionSource: strings.TrimSpace(attributionSource),
	}
	if found {
		cand = existing
		cand.FailureCount += times
		cand.LastObserved = &observed
		// A later DNS-correlated observation upgrades the evidence; a plain re-observation never downgrades it.
		if ip := strings.TrimSpace(observedIP); ip != "" {
			cand.ObservedIP = ip
		}
		if src := strings.TrimSpace(attributionSource); src != "" {
			cand.AttributionSource = src
		}
	}
	// Classify attribution from the candidate's evidence: DNS-correlated -> high, a named host/SNI -> medium, a
	// raw-IP-only candidate -> investigate_only. Recomputed each observation so it stays correct.
	cand.Confidence, cand.SuggestedAction = certPinAttribution(cand.Host, cand.SNI, cand.AttributionSource)
	return cand
}

// AddManualCertPinBypass records an operator-authored cert-pin bypass for a named host and marks it APPROVED
// in one step (ready to materialize). Unlike a detected candidate it never sits in pending — the operator is
// explicitly declaring a known-broken pinned site that the detector may not have surfaced (or that they simply
// don't want to wait to be detected). It is otherwise an ordinary cert-pin candidate: it carries the same
// SourceCertPinningDetection so it flows through the identical materialize path (emitting an Egress bypass
// rule) and appears in the same lists, toggles, and revoke controls as a detected-then-adopted one. It NEVER
// bypasses on its own — the caller must still Materialize it — so the never-auto-bypass invariant holds; the
// bypass becomes live only because a human explicitly asked for it.
//
// The host must be a named host, not a raw IP literal: a bypass no-decrypts its destination, and you cannot
// tell what site a bare IP is (this is the same "approve an ENTITY, not an IP" rule the detector encodes as
// investigate_only). If this host was already a candidate (e.g. previously auto-detected) its observation
// history is kept and it is simply advanced to approved so it can be materialized.
func (store *Store) AddManualCertPinBypass(ctx context.Context, tenantID, host string, now time.Time) (Candidate, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Candidate{}, fmt.Errorf("tenant_id is required")
	}
	var err error
	host, err = NormalizeCertPinHostname(host)
	if err != nil {
		return Candidate{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	observed := now.UTC().Format(time.RFC3339)
	const reason = "operator_manual_add"
	id := CertPinCandidateID(host, "", 443, reason)

	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.persister.(candidateSharedPersister); ok {
		return sharedCandidateMutation(store, ctx, func(next *Store) (Candidate, error) { return next.AddManualCertPinBypass(ctx, tenantID, host, now) })
	}

	cand := Candidate{
		CandidateID:    id,
		TenantID:       tenantID,
		Source:         SourceCertPinningDetection,
		CandidateType:  "bypass_policy",
		ProposedAction: "bypass",
		Host:           host,
		Port:           443,
		ServiceFamily:  "https",
		ReasonCodes:    []string{reason},
		LastObserved:   &observed,
		Status:         "approved",
	}
	if existing, ok := store.candidates[tenantID][id]; ok {
		cand = existing
		cand.Status = "approved"
	}
	cand.Confidence, cand.SuggestedAction = certPinAttribution(cand.Host, cand.SNI, cand.AttributionSource)
	normalized, err := normalizeObservation(cand, tenantID, now)
	if err != nil {
		return Candidate{}, err
	}
	if err := store.putLocked(normalized); err != nil {
		return Candidate{}, err
	}
	return copyCandidate(normalized), nil
}

// Materialize saves an approved candidate's adoption request. Rule creation is a
// separate operation, so this status is not an enforcement receipt. A cert-pin
// request can be retried after a later asset/rule save failed.
func (store *Store) Materialize(ctx context.Context, tenantID, candidateID string, allowHighRisk bool, now time.Time) (Candidate, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	candidateID = strings.TrimSpace(candidateID)
	if tenantID == "" || candidateID == "" {
		return Candidate{}, false, fmt.Errorf("tenant_id and candidate_id are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ts := now.UTC().Format(time.RFC3339)

	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.persister.(candidateSharedPersister); ok {
		result, err := sharedCandidateMutation(store, ctx, func(next *Store) (candidateLookup, error) {
			c, found, err := next.Materialize(ctx, tenantID, candidateID, allowHighRisk, now)
			return candidateLookup{c, found}, err
		})
		return result.candidate, result.found, err
	}

	cand, ok := store.candidates[tenantID][candidateID]
	if !ok {
		return Candidate{}, false, nil
	}
	if cand.Status != "approved" && !((cand.Source == SourceCertPinningDetection || cand.CandidateType == "allow_policy") && cand.Status == "materialized") {
		return Candidate{}, false, fmt.Errorf("only an approved candidate can be materialized (status=%s)", cand.Status)
	}
	// Advisory labels are persisted/importable metadata, not an authorization
	// boundary. Recompute the actual scope before saving an adoption request.
	highRisk := cand.SuggestedAction == suggestedActionInvestigateOnly
	if cand.Source == SourceCertPinningDetection {
		_, actualRisk, err := CertPinBypassTarget(cand)
		if err != nil {
			return Candidate{}, true, err
		}
		highRisk = actualRisk
		cand.Confidence, cand.SuggestedAction = certPinAttribution(cand.Host, cand.SNI, cand.AttributionSource)
	}
	if highRisk && !allowHighRisk {
		return Candidate{}, true, fmt.Errorf("materialize blocked: unattributed candidate %q (investigate_only) requires an explicit high-risk override", candidateID)
	}
	cand.Status = "materialized"
	cand.UpdatedAt = &ts
	if err := store.putLocked(cand); err != nil {
		return Candidate{}, true, err
	}
	return copyCandidate(cand), true, nil
}
