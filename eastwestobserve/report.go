package eastwestobserve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/reportreceipt"
)

// An Edge is a fleet member that can be started or stopped at any time, so the flows it observes are held by the
// control plane, not by the Edge. An Edge reports what it saw since its last report; the control plane folds
// each report into this inventory exactly once.
//
// Exactly once, because the delivery channel is at-least-once: a report whose acknowledgement was lost, or that
// was still in the sender's spool when the sender restarted, arrives again. Counts are additive, so a report
// applied twice would count its flows twice. Each report therefore carries its reporter (one sending process)
// and an increasing sequence number. Delivery can reorder reports. The inventory keeps the highest applied
// sequence and unapplied gaps IN THE SAME ROW as the counts, so the counts
// and the record of having applied them commit or roll back together.

// rowFormat marks a row that carries report receipts beside the flows. A row without receipts is still written
// in the original shape (a tenant map), which is what earlier builds read. v3 makes older readers refuse
// receipts with gaps rather than silently treating the high watermark as a contiguous prefix.
const rowFormat = "eastwest_observations.v4"

// receiptRetention bounds the receipts kept. Every Edge process start is a new reporter, so without a bound the
// receipts would grow with the fleet's history. A report replayed after its receipt is gone would be counted
// again; a sender does not hold an unacknowledged report for a month.
const receiptRetention = 30 * 24 * time.Hour

// ReportReceipt tracks applied sequences and holes left by reordered delivery.
type ReportReceipt = reportreceipt.Receipt

var errReportAlreadyApplied = errors.New("observation report already applied")

// ErrInvalidReport marks a report that no retry can make applicable: the sender should set it aside.
var ErrInvalidReport = errors.New("invalid observation report")

// splitRow separates a stored row into its flows and receipts. A row in the original shape is all flows.
func splitRow(raw []byte) ([]byte, map[string]ReportReceipt, error) {
	var probe map[string]json.RawMessage
	if json.Unmarshal(raw, &probe) != nil {
		return raw, nil, nil // not an object: the flow decoder refuses it
	}
	var format string
	if f, ok := probe["format"]; !ok || json.Unmarshal(f, &format) != nil {
		return raw, nil, nil // a tenant map: every value is an object, never a string
	}
	if (format != rowFormat && format != "eastwest_observations.v3" && format != "eastwest_observations.v2") || len(probe) != 3 || probe["flows"] == nil || probe["receipts"] == nil {
		return nil, nil, fmt.Errorf("unknown observation row format")
	}
	var receipts map[string]ReportReceipt
	if json.Unmarshal(probe["receipts"], &receipts) != nil || receipts == nil {
		return nil, nil, fmt.Errorf("invalid observation report receipts")
	}
	for reporter, r := range receipts {
		if reporter == "" || !r.Valid() {
			return nil, nil, fmt.Errorf("invalid observation report receipt")
		}
	}
	return probe["flows"], receipts, nil
}

func encodeRow(flows map[string]map[string]FlowObservation, receipts map[string]ReportReceipt) ([]byte, error) {
	if len(receipts) == 0 {
		return json.Marshal(flows)
	}
	return json.Marshal(struct {
		Format   string                                `json:"format"`
		Flows    map[string]map[string]FlowObservation `json:"flows"`
		Receipts map[string]ReportReceipt              `json:"receipts"`
	}{rowFormat, flows, receipts})
}

func pruneReceipts(receipts map[string]ReportReceipt, now time.Time) {
	cutoff := now.Add(-receiptRetention)
	for reporter, r := range receipts {
		if at, err := time.Parse(time.RFC3339, r.At); err == nil && at.Before(cutoff) {
			delete(receipts, reporter)
		}
	}
}

// reportDeltas checks a report's flows and keys them as the inventory does. Two entries for one flow are merged.
func reportDeltas(tenantID string, flows []FlowObservation) (map[string]FlowObservation, error) {
	out := map[string]FlowObservation{}
	for _, o := range flows {
		o.TenantID = tenantID
		o.Destination = strings.TrimSpace(o.Destination)
		o.Source = strings.TrimSpace(o.Source)
		if o.Source == "" {
			o.Source = SourceAny
		}
		o.User = strings.TrimSpace(o.User)
		o.ServiceFamily = normalize(o.ServiceFamily)
		first, e1 := time.Parse(time.RFC3339, o.FirstSeen)
		last, e2 := time.Parse(time.RFC3339, o.LastSeen)
		if o.Destination == "" || o.Count < 1 || o.Port < 0 || o.Port > 65535 || e1 != nil || e2 != nil || first.After(last) {
			return nil, fmt.Errorf("%w: a flow is missing its destination, count or times", ErrInvalidReport)
		}
		o.ObservationID = ObservationKey(o.Source, o.Destination, o.ServiceFamily, o.Port)
		o.Covered = false
		batch := map[string]map[string]FlowObservation{tenantID: out}
		if err := mergePending(batch, map[string]map[string]FlowObservation{tenantID: {o.ObservationID: o}}); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidReport, err)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no flows", ErrInvalidReport)
	}
	return out, nil
}

// ApplyReport folds one report into the inventory unless this reporter's report seq is already
// in it. applied is false for a report that was already applied, which is not an error: the sender may deliver a
// report more than once. On a shared store the counts and the receipt commit in one transaction, so a report
// whose commit outcome is unknown is safe to deliver again.
func (s *Store) ApplyReport(ctx context.Context, tenantID, reporter string, seq uint64, flows []FlowObservation, now time.Time) (applied bool, err error) {
	tenantID, reporter = strings.TrimSpace(tenantID), strings.TrimSpace(reporter)
	if tenantID == "" || reporter == "" || seq == 0 {
		return false, fmt.Errorf("%w: a report needs a tenant, a reporter and a sequence", ErrInvalidReport)
	}
	add, err := reportDeltas(tenantID, flows)
	if err != nil {
		return false, err
	}
	if now.IsZero() {
		now = time.Now()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.persister.(sharedPersister); ok {
		if s.sharedUncertain {
			return false, fmt.Errorf("observation commit requires reconciliation")
		}
		var next map[string]map[string]FlowObservation
		duplicate := false
		err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
			flows, receipts, e := decodeShared(raw, s.sharedKnown)
			if e != nil {
				return nil, e
			}
			nextReceipt, err := receipts[reporter].Applied(seq, now)
			if err != nil {
				return nil, err
			}
			if receipts[reporter].Contains(seq) {
				duplicate = true
				return nil, errReportAlreadyApplied
			}
			if e = mergePending(flows, map[string]map[string]FlowObservation{tenantID: add}); e != nil {
				return nil, e
			}
			(&Store{flows: flows, retention: s.retention}).pruneLocked(now)
			if receipts == nil {
				receipts = map[string]ReportReceipt{}
			}
			receipts[reporter] = nextReceipt
			pruneReceipts(receipts, now)
			next = flows
			return encodeRow(flows, receipts)
		})
		if duplicate {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("observation report not applied: %w", err)
		}
		view := cloneFlows(next)
		if err := mergePending(view, s.sharedPending); err != nil {
			return true, err
		}
		s.flows = view
		s.sharedKnown = true
		s.pruneLocked(now)
		return true, nil
	}
	nextReceipt, err := s.receipts[reporter].Applied(seq, now)
	if err != nil {
		return false, err
	}
	if s.receipts[reporter].Contains(seq) {
		return false, nil
	}
	if err := mergePending(s.flows, map[string]map[string]FlowObservation{tenantID: add}); err != nil {
		return false, err
	}
	if s.receipts == nil {
		s.receipts = map[string]ReportReceipt{}
	}
	s.receipts[reporter] = nextReceipt
	pruneReceipts(s.receipts, now)
	s.pruneLocked(now)
	s.dirty = true
	return true, nil
}
