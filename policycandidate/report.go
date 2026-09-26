package policycandidate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/reportreceipt"
)

// An Edge is a fleet member that can be started or stopped at any time, so the candidates its traffic produces
// are held by the control plane. An Edge reports what it saw since its last report; the control plane folds each
// report into this store exactly once.
//
// The delivery channel is at-least-once, and an observation increments a counter, so each report carries its
// reporter (one sending process) and a sequence that increases with every report that reporter sends, in the
// order it sends them. Delivery may reorder them, so the highest sequence and unapplied gaps are kept in the same row as the candidates, so
// the candidates and the record of having applied a report commit or roll back together. That is also why an
// unknown commit outcome does not stop this store for a report as it does for a local observation: delivering
// the report again is recognised rather than counted twice.

// Kinds of reported observation, one per Observe entry point.
const (
	ReportUnmatchedFlow          = "unmatched_flow"
	ReportCertPinFailure         = "cert_pin_failure"
	ReportCertPinFailureDNSMatch = "cert_pin_failure_dns"
)

// ReportedObservation is one sighting an Edge reports, with how many times it saw it since its last report.
type ReportedObservation struct {
	Kind         string `json:"kind"`
	Host         string `json:"host,omitempty"`
	SNI          string `json:"sni,omitempty"`
	ObservedIP   string `json:"observed_ip,omitempty"`
	Port         int    `json:"port"`
	Reason       string `json:"reason,omitempty"`
	Count        int    `json:"count"`
	LastObserved string `json:"last_observed"`
}

// ReportReceipt tracks applied sequences and holes left by reordered delivery.
type ReportReceipt = reportreceipt.Receipt

// rowFormat marks a row carrying report receipts beside the candidates. A row without receipts keeps the original
// shape (a tenant map), which earlier builds read. v3 prevents older readers from silently ignoring gaps.
const rowFormat = "policy_candidates.v4"

// receiptRetention bounds the receipts: every Edge process start is a new reporter. A report replayed after its
// receipt is gone would be counted again; a sender does not hold an unacknowledged report for a month.
const receiptRetention = 30 * 24 * time.Hour

var errReportAlreadyApplied = errors.New("policy candidate report already applied")

// ErrInvalidReport marks a report that no retry can make applicable: the sender should set it aside.
var ErrInvalidReport = errors.New("invalid policy candidate report")

// decodeCandidateRow reads a stored row in either shape.
func decodeCandidateRow(data []byte) (map[string]map[string]Candidate, map[string]ReportReceipt, error) {
	var probe map[string]json.RawMessage
	if json.Unmarshal(data, &probe) != nil {
		snapshot, err := decodeCandidateSnapshot(data)
		return snapshot, nil, err
	}
	var format string
	if f, ok := probe["format"]; !ok || json.Unmarshal(f, &format) != nil {
		snapshot, err := decodeCandidateSnapshot(data) // a tenant map: every value is an object, never a string
		return snapshot, nil, err
	}
	if (format != rowFormat && format != "policy_candidates.v3" && format != "policy_candidates.v2") || len(probe) != 3 || probe["candidates"] == nil || probe["receipts"] == nil {
		return nil, nil, errInvalidSnapshot
	}
	var receipts map[string]ReportReceipt
	if json.Unmarshal(probe["receipts"], &receipts) != nil || receipts == nil {
		return nil, nil, errInvalidSnapshot
	}
	for reporter, r := range receipts {
		if reporter == "" || !r.Valid() {
			return nil, nil, errInvalidSnapshot
		}
	}
	snapshot, err := decodeCandidateSnapshot(probe["candidates"])
	if err != nil {
		return nil, nil, err
	}
	return snapshot, receipts, nil
}

func encodeCandidateRow(candidates map[string]map[string]Candidate, receipts map[string]ReportReceipt) ([]byte, error) {
	if len(receipts) == 0 {
		return json.MarshalIndent(candidates, "", "  ")
	}
	return json.MarshalIndent(struct {
		Format     string                          `json:"format"`
		Candidates map[string]map[string]Candidate `json:"candidates"`
		Receipts   map[string]ReportReceipt        `json:"receipts"`
	}{rowFormat, candidates, receipts}, "", "  ")
}

func pruneReceipts(receipts map[string]ReportReceipt, now time.Time) {
	cutoff := now.Add(-receiptRetention)
	for reporter, r := range receipts {
		if at, err := time.Parse(time.RFC3339, r.At); err == nil && at.Before(cutoff) {
			delete(receipts, reporter)
		}
	}
}

func copyReceipts(src map[string]ReportReceipt) map[string]ReportReceipt {
	if src == nil {
		return nil
	}
	dst := make(map[string]ReportReceipt, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// applyReportedObservation folds one reported sighting into candidates.
func applyReportedObservation(candidates map[string]map[string]Candidate, tenantID string, o ReportedObservation, now time.Time) error {
	last, err := time.Parse(time.RFC3339, strings.TrimSpace(o.LastObserved))
	if err != nil || o.Count < 1 || o.Port < 0 || o.Port > 65535 {
		return fmt.Errorf("%w: an observation is missing its count, port or time", ErrInvalidReport)
	}
	observed := last.UTC().Format(time.RFC3339)
	host, sni := normalizeHostValue(o.Host), normalizeHostValue(o.SNI)
	reason := strings.TrimSpace(o.Reason)
	var id string
	var cand Candidate
	switch o.Kind {
	case ReportUnmatchedFlow:
		applicationID := host
		if applicationID == "" {
			applicationID = sni
		}
		if applicationID == "" {
			return fmt.Errorf("%w: an observed flow needs a host or sni", ErrInvalidReport)
		}
		if reason == "" {
			reason = "observed_unmatched_flow"
		}
		id = LearningCandidateID(host, sni, o.Port)
		existing, found := candidates[tenantID][id]
		cand = unmatchedFlowCandidate(existing, found, id, tenantID, applicationID, host, sni, o.Port, reason, observed, o.Count)
	case ReportCertPinFailure, ReportCertPinFailureDNSMatch:
		// The detectors pass these as they saw them; the key is built from the same values.
		host, sni, ip, source := strings.TrimSpace(o.Host), strings.TrimSpace(o.SNI), strings.TrimSpace(o.ObservedIP), ""
		if o.Kind == ReportCertPinFailureDNSMatch {
			if host == "" || ip == "" {
				return fmt.Errorf("%w: a DNS-correlated detection needs the name and the address", ErrInvalidReport)
			}
			sni, source = "", attributionSourceDNSTunnel
		} else {
			ip = ""
		}
		if host == "" && sni == "" {
			return fmt.Errorf("%w: a cert-pin detection needs a host or sni", ErrInvalidReport)
		}
		id = CertPinCandidateID(host, sni, o.Port, reason)
		existing, found := candidates[tenantID][id]
		cand = certPinCandidate(existing, found, id, tenantID, host, sni, ip, source, o.Port, reason, observed, o.Count)
	default:
		return fmt.Errorf("%w: unknown observation kind", ErrInvalidReport)
	}
	// Reports from several Edges arrive in any order; the latest sighting stays the latest.
	if existing, ok := candidates[tenantID][id]; ok && existing.LastObserved != nil && *existing.LastObserved > observed {
		kept := *existing.LastObserved
		cand.LastObserved = &kept
	}
	normalized, err := normalize(cand, tenantID, now)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidReport, err)
	}
	if candidates[tenantID] == nil {
		candidates[tenantID] = map[string]Candidate{}
	}
	candidates[tenantID][id] = normalized
	return nil
}

// ApplyReport folds one reporter's report into the store unless that report from the same
// reporter is already in it. applied is false for a report already applied, which is not an error: the sender
// may deliver a report more than once. Nothing is applied if any observation in the report is invalid.
func (store *Store) ApplyReport(ctx context.Context, tenantID, reporter string, seq uint64, observations []ReportedObservation, now time.Time) (applied bool, err error) {
	tenantID, reporter = strings.TrimSpace(tenantID), strings.TrimSpace(reporter)
	if tenantID == "" || reporter == "" || seq == 0 || len(observations) == 0 {
		return false, fmt.Errorf("%w: a report needs a tenant, a reporter, a sequence and observations", ErrInvalidReport)
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	apply := func(candidates map[string]map[string]Candidate, receipts map[string]ReportReceipt) (map[string]ReportReceipt, error) {
		nextReceipt, err := receipts[reporter].Applied(seq, now)
		if err != nil {
			return nil, err
		}
		if receipts[reporter].Contains(seq) {
			return nil, errReportAlreadyApplied
		}
		for _, o := range observations {
			if err := applyReportedObservation(candidates, tenantID, o, now); err != nil {
				return nil, err
			}
		}
		receipts = copyReceipts(receipts)
		if receipts == nil {
			receipts = map[string]ReportReceipt{}
		}
		receipts[reporter] = nextReceipt
		pruneReceipts(receipts, now)
		return receipts, nil
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.persister.(candidateSharedPersister); ok {
		_, err := sharedCandidateMutationLatching(store, ctx, false, func(next *Store) (struct{}, error) {
			receipts, e := apply(next.candidates, next.receipts)
			if e == nil {
				next.receipts = receipts
			}
			return struct{}{}, e
		})
		if errors.Is(err, errReportAlreadyApplied) {
			return false, nil
		}
		return err == nil, err
	}
	next := store.cloneLocked()
	receipts, err := apply(next, store.receipts)
	if errors.Is(err, errReportAlreadyApplied) {
		if store.dirty {
			return false, store.commitWithReceiptsLocked(store.candidates, store.receipts)
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := store.commitWithReceiptsLocked(next, receipts); err != nil {
		return false, err
	}
	return true, nil
}
