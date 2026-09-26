package policycandidate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
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
	if strings.TrimSpace(attributionSource) == attributionSourceDNSTunnel {
		return "high", "review"
	}
	h := strings.TrimSpace(host)
	s := strings.TrimSpace(sni)
	if s != "" || (h != "" && net.ParseIP(h) == nil) {
		return "medium", "review"
	}
	return "low", suggestedActionInvestigateOnly
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
func (store *Store) ObserveCertPinFailure(_ context.Context, tenantID, host, sni string, port int, reason string, now time.Time) (Candidate, error) {
	return store.observeCertPin(tenantID, host, sni, "", "", port, reason, now)
}

// ObserveCertPinFailureDNSCorrelated records a cert-pin detection for a connect-by-IP flow (no SNI) whose real
// FQDN was recovered from the DNS-over-tunnel conntrack. The candidate is keyed by the recovered ENTITY (the
// FQDN, not the raw IP) so detections to the same name dedup, it carries "high" confidence (DNS correlation is
// the strongest attribution evidence), and the originating IP is retained as evidence. This is how a raw-IPv6/
// CDN candidate that would otherwise be investigate_only becomes a normal, named admin review item.
func (store *Store) ObserveCertPinFailureDNSCorrelated(_ context.Context, tenantID, fqdn, observedIP string, port int, reason string, now time.Time) (Candidate, error) {
	return store.observeCertPin(tenantID, fqdn, "", observedIP, attributionSourceDNSTunnel, port, reason, now)
}

func (store *Store) observeCertPin(tenantID, host, sni, observedIP, attributionSource string, port int, reason string, now time.Time) (Candidate, error) {
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
		FailureCount:      1,
		LastObserved:      &observed,
		ObservedIP:        strings.TrimSpace(observedIP),
		AttributionSource: strings.TrimSpace(attributionSource),
	}
	if existing, ok := store.candidates[tenantID][id]; ok {
		cand = existing
		cand.FailureCount++
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
	normalized, err := normalize(cand, tenantID, now)
	if err != nil {
		return Candidate{}, err
	}
	if err := store.putLocked(normalized); err != nil {
		return copyCandidate(normalized), err
	}
	return copyCandidate(normalized), nil
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
func (store *Store) AddManualCertPinBypass(_ context.Context, tenantID, host string, now time.Time) (Candidate, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Candidate{}, fmt.Errorf("tenant_id is required")
	}
	host = normalizeHostValue(host)
	if host == "" {
		return Candidate{}, fmt.Errorf("host is required")
	}
	if net.ParseIP(host) != nil {
		return Candidate{}, fmt.Errorf("host %q must be a named host, not a raw IP literal", host)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	observed := now.UTC().Format(time.RFC3339)
	const reason = "operator_manual_add"
	id := CertPinCandidateID(host, "", 443, reason)

	store.mu.Lock()
	defer store.mu.Unlock()

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
	normalized, err := normalize(cand, tenantID, now)
	if err != nil {
		return Candidate{}, err
	}
	if err := store.putLocked(normalized); err != nil {
		return copyCandidate(normalized), err
	}
	return copyCandidate(normalized), nil
}

// Materialize marks an approved candidate as materialized — its bypass has been written into the SWG TLS
// bypass policy (the only state in which traffic is actually decrypt-bypassed). Only an approved
// candidate can be materialized; this is what separates "approved but not applied" from "applied".
func (store *Store) Materialize(_ context.Context, tenantID, candidateID string, allowHighRisk bool, now time.Time) (Candidate, bool, error) {
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

	cand, ok := store.candidates[tenantID][candidateID]
	if !ok {
		return Candidate{}, false, nil
	}
	if cand.Status != "approved" {
		return Candidate{}, false, fmt.Errorf("only an approved candidate can be materialized (status=%s)", cand.Status)
	}
	// Safety gate: an UNATTRIBUTED candidate (a raw IP literal with no SNI -> suggested_action investigate_only)
	// must not be no-decrypted without an explicit high-risk override. You cannot tell what site/app a bare
	// IPv6/CDN address is, and no-decrypt of a raw IP/prefix is forbidden by default in the design.
	if cand.SuggestedAction == suggestedActionInvestigateOnly && !allowHighRisk {
		return Candidate{}, true, fmt.Errorf("materialize blocked: unattributed candidate %q (investigate_only) requires an explicit high-risk override", candidateID)
	}
	cand.Status = "materialized"
	cand.UpdatedAt = &ts
	if err := store.putLocked(cand); err != nil {
		return copyCandidate(cand), true, err
	}
	return copyCandidate(cand), true, nil
}
