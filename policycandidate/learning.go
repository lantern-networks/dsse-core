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

// SourceUnmatchedFlow marks a candidate proposed from traffic: a destination seen on
// an unmatched (would-be default-denied) flow while the tenant is still observing. It is surfaced for an
// admin to bring under explicit policy. Proposing never enforces — the destination keeps flowing under
// observe mode until an admin reviews and materializes the candidate.
const SourceUnmatchedFlow = "unmatched_flow"

// LearningCandidateID derives a stable candidate id from the destination (host/sni/port) so repeated
// observations of the same destination upsert one candidate (incrementing its observation count) rather
// than duplicating it.
func LearningCandidateID(host, sni string, port int) string {
	key := normalizeHostValue(host) + "|" + normalizeHostValue(sni) + "|" + strconv.Itoa(port)
	sum := sha256.Sum256([]byte(key))
	return "learn-" + hex.EncodeToString(sum[:10])
}

// ObserveUnmatchedFlow records a destination seen on an unmatched flow during observe mode. It creates a
// pending allow-policy candidate the first time, and increments the observation count + refreshes
// last_observed on subsequent observations. It NEVER enforces anything — the flow keeps passing under
// observe mode; an admin reviews and materializes the candidate to bring the destination under explicit
// policy (the generalization of cert-pinning's ObserveCertPinFailure to all observed traffic). An
// already-decided candidate keeps its status while still counting observations.
func (store *Store) ObserveUnmatchedFlow(ctx context.Context, tenantID, host, sni string, port int, category string, now time.Time) (Candidate, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Candidate{}, fmt.Errorf("tenant_id is required")
	}
	host = normalizeHostValue(host)
	sni = normalizeHostValue(sni)
	// The destination is identified by host/sni; require at least one so the candidate is actionable.
	applicationID := host
	if applicationID == "" {
		applicationID = sni
	}
	if applicationID == "" {
		return Candidate{}, fmt.Errorf("observed flow requires host or sni")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	observed := now.UTC().Format(time.RFC3339)
	id := LearningCandidateID(host, sni, port)

	reason := strings.TrimSpace(category)
	if reason == "" {
		reason = "observed_unmatched_flow"
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.persister.(candidateSharedPersister); ok {
		return sharedCandidateMutation(store, ctx, func(next *Store) (Candidate, error) {
			return next.ObserveUnmatchedFlow(ctx, tenantID, host, sni, port, category, now)
		})
	}

	existing, found := store.candidates[tenantID][id]
	cand := unmatchedFlowCandidate(existing, found, id, tenantID, applicationID, host, sni, port, reason, observed, 1)
	normalized, err := normalizeObservation(cand, tenantID, now)
	if err != nil {
		return Candidate{}, err
	}
	if err := store.putLocked(normalized); err != nil {
		return Candidate{}, err
	}
	return copyCandidate(normalized), nil
}

// unmatchedFlowCandidate is the candidate after times more sightings of an unmatched flow.
func unmatchedFlowCandidate(existing Candidate, found bool, id, tenantID, applicationID, host, sni string, port int, reason, observed string, times int) Candidate {
	if found {
		existing.FailureCount += times
		existing.LastObserved = &observed
		return existing
	}
	return Candidate{
		CandidateID:    id,
		TenantID:       tenantID,
		Source:         SourceUnmatchedFlow,
		CandidateType:  "allow_policy",
		ProposedAction: "allow",
		// The observed destination is its own "application" — host/sni identify it; ApplicationID carries
		// that identity to satisfy the allow-policy candidate shape without inventing a catalog entry.
		ApplicationID: applicationID,
		ServiceFamily: learningServiceFamilyForPort(port),
		Host:          host,
		SNI:           sni,
		Port:          port,
		ReasonCodes:   []string{reason},
		FailureCount:  times,
		LastObserved:  &observed,
	}
}

// learningServiceFamilyForPort maps a destination port to a non-secret service family label. Defaults to
// "https" since observe mode operates on intercepted TLS; other ports fall back to a generic label.
func learningServiceFamilyForPort(port int) string {
	switch port {
	case 0, 443:
		return "https"
	case 80:
		return "http"
	default:
		return "tcp"
	}
}
