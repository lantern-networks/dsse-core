package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/eastwestobserve"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policycandidate"
)

// observation_report.go — the traffic an Edge observes is held by the control plane.
//
// ★★★ AN EDGE IS A FLEET MEMBER THAT CAN BE STARTED OR STOPPED AT ANY TIME (operator's decision, 2026-09-23).
// East-west flow observations and policy candidates (default-deny destinations, cert-pinning failures) are
// produced on the traffic path, which only an Edge has. They used to stay in that Edge's memory: an Edge restart
// erased every unreviewed candidate and every review decision, and on three regions a Console saw only what its
// own machine's Edge had seen. The control plane's shared stores, built to hold them, were fed by nothing.
//
// So an Edge reports. It keeps the counts it saw since its last report, and every observationReportInterval
// writes them as one record per organization to a shipped stream. A dedicated shipper carries the streams to
// the control plane's /audit-ingest, which folds each record into the shared store before acknowledging it.
//
// ★ EXACTLY ONCE OVER AN AT-LEAST-ONCE CHANNEL. A record is re-sent when its acknowledgement is lost and when it
// was still spooled as the Edge restarted. Counts add, so each record carries this process's reporter id and a
// sequence number that grows with every record on its stream; the store applies a (reporter, sequence) once and
// keeps that fact in the same row as the counts, including gaps below the highest sequence. The shipper may
// rotate refused records behind later ones; a lower sequence is not necessarily a replay.
//
// ★ ITS OWN SHIPPER. The control plane acknowledges a report only after the store commits it, so while the
// database is away the report waits at the head of the queue. On the audit shipper that would hold every audit
// record behind it; on its own shipper it holds only other reports.
//
// What can still be lost: up to one interval of counts on an Edge that is killed without SIGTERM (SIGTERM
// flushes), and records the shipper's bounded spool drops, which it logs.

const (
	eastWestObservationReportStream  = "east_west_observation_reports.log.jsonl"
	candidateObservationReportStream = "policy_candidate_observation_reports.log.jsonl"
	observationReportInterval        = 5 * time.Second
	// A flush happens early once this many distinct observations are waiting, so memory stays bounded however
	// busy the Edge is.
	observationReportMaxPending = 5000
	// Entries per record, so one record stays well under the ingest body limit.
	observationReportMaxPerRecord = 500
)

var observationReportStreams = []string{eastWestObservationReportStream, candidateObservationReportStream}

// observationReportRecord is one shipped report: one organization, one stream, one sequence.
type observationReportRecord struct {
	Kind         string                                `json:"kind"`
	EventID      string                                `json:"event_id"`
	TenantID     string                                `json:"tenant_id"`
	Reporter     string                                `json:"reporter"`
	Seq          uint64                                `json:"seq"`
	Timestamp    string                                `json:"timestamp"`
	Flows        []eastwestobserve.FlowObservation     `json:"flows,omitempty"`
	Observations []policycandidate.ReportedObservation `json:"observations,omitempty"`
}

// restart-durability: bounded_buffer — counts observed since the last report, at most
// observationReportMaxPending distinct entries or observationReportInterval old. Written on each interval and on
// SIGTERM to the report streams, which the dedicated shipper spools and the control plane stores; a kill without
// SIGTERM loses at most one interval.
// populated-by: side_effect — the steer-mux decision path (east-west Observe, default-deny candidate), the SWG
// egress path (default-deny and unrecognised-name candidates) and the interception handshake-rejection emitter:
// every call site of the local candidate and east-west stores' Observe methods reports beside it.
type observationReporter struct {
	mu         sync.Mutex
	writer     *logs.Writer
	reporter   string
	eastWest   map[string]map[string]eastwestobserve.FlowObservation
	candidates map[string]map[string]policycandidate.ReportedObservation
	pending    int
	seq        map[string]uint64
	kick       chan struct{}
	quit, done chan struct{}
	stopOnce   sync.Once
	now        func() time.Time
	shipper    *remoteAuditShipper
}

// observationReports is armed on an Edge that ships to a control plane and holds no shared database. Nil means
// observations stay with whatever recorded them locally.
var observationReports atomic.Pointer[observationReporter]

func newObservationReporter(writer *logs.Writer) (*observationReporter, error) {
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("observation reporter id: %w", err)
	}
	return &observationReporter{
		writer:     writer,
		reporter:   hex.EncodeToString(id),
		eastWest:   map[string]map[string]eastwestobserve.FlowObservation{},
		candidates: map[string]map[string]policycandidate.ReportedObservation{},
		seq:        map[string]uint64{},
		kick:       make(chan struct{}, 1),
		quit:       make(chan struct{}),
		done:       make(chan struct{}),
		now:        time.Now,
	}, nil
}

func (r *observationReporter) start() {
	go func() {
		defer close(r.done)
		t := time.NewTicker(observationReportInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
			case <-r.kick:
			case <-r.quit:
				r.flush()
				return
			}
			r.flush()
		}
	}()
}

// stop writes what is waiting and ends the loop. Safe to call more than once.
func (r *observationReporter) stop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() { close(r.quit) })
	<-r.done
}

func (r *observationReporter) noteLocked() {
	r.pending++
	if r.pending >= observationReportMaxPending {
		select {
		case r.kick <- struct{}{}:
		default:
		}
	}
}

// eastWestFlow counts one lateral-flow sighting. Arguments are those of eastwestobserve.Store.Observe.
func (r *observationReporter) eastWestFlow(tenantID, source, user, destination, serviceFamily string, port int, now time.Time) {
	if r == nil {
		return
	}
	tenantID, destination = strings.TrimSpace(tenantID), strings.TrimSpace(destination)
	if tenantID == "" || destination == "" {
		return
	}
	if source = strings.TrimSpace(source); source == "" {
		source = eastwestobserve.SourceAny
	}
	serviceFamily = strings.ToLower(strings.TrimSpace(serviceFamily))
	ts := now.UTC().Format(time.RFC3339)
	key := eastwestobserve.ObservationKey(source, destination, serviceFamily, port)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.eastWest[tenantID] == nil {
		r.eastWest[tenantID] = map[string]eastwestobserve.FlowObservation{}
	}
	o, ok := r.eastWest[tenantID][key]
	if !ok {
		o = eastwestobserve.FlowObservation{Source: source, Destination: destination, ServiceFamily: serviceFamily, Port: port, FirstSeen: ts}
		r.noteLocked()
	}
	if ts < o.FirstSeen {
		o.FirstSeen = ts
	}
	if ts >= o.LastSeen {
		o.LastSeen = ts
		o.User = strings.TrimSpace(user) // the latest sighting names the user, as the store does
	}
	o.Count++
	r.eastWest[tenantID][key] = o
}

// candidate counts one sighting that produces a policy candidate. Arguments are those of the matching
// policycandidate.Store Observe call.
func (r *observationReporter) candidate(kind, tenantID, host, sni, observedIP string, port int, reason string, now time.Time) {
	if r == nil {
		return
	}
	if tenantID = strings.TrimSpace(tenantID); tenantID == "" {
		return
	}
	ts := now.UTC().Format(time.RFC3339)
	key := strings.Join([]string{kind, host, sni, observedIP, strconv.Itoa(port), reason}, "\x00")
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.candidates[tenantID] == nil {
		r.candidates[tenantID] = map[string]policycandidate.ReportedObservation{}
	}
	o, ok := r.candidates[tenantID][key]
	if !ok {
		o = policycandidate.ReportedObservation{Kind: kind, Host: host, SNI: sni, ObservedIP: observedIP, Port: port, Reason: reason}
		r.noteLocked()
	}
	if ts > o.LastObserved {
		o.LastObserved = ts
	}
	o.Count++
	r.candidates[tenantID][key] = o
}

// flush writes one record per organization and stream. A record that cannot be written was never shipped (the
// writer hands a line to the shipper only after writing it), so its observations are kept and the same sequence
// is used again.
func (r *observationReporter) flush() {
	r.mu.Lock()
	eastWest, candidates := r.eastWest, r.candidates
	r.eastWest = map[string]map[string]eastwestobserve.FlowObservation{}
	r.candidates = map[string]map[string]policycandidate.ReportedObservation{}
	r.pending = 0
	r.mu.Unlock()

	for _, tenant := range sortedKeys(eastWest) {
		flows := make([]eastwestobserve.FlowObservation, 0, len(eastWest[tenant]))
		for _, k := range sortedKeys(eastWest[tenant]) {
			flows = append(flows, eastWest[tenant][k])
		}
		for len(flows) > 0 {
			n := min(len(flows), observationReportMaxPerRecord)
			if !r.write(eastWestObservationReportStream, observationReportRecord{Kind: "east_west_observation_report", TenantID: tenant, Flows: flows[:n]}) {
				r.restoreEastWest(tenant, flows)
				break
			}
			flows = flows[n:]
		}
	}
	for _, tenant := range sortedKeys(candidates) {
		obs := make([]policycandidate.ReportedObservation, 0, len(candidates[tenant]))
		for _, k := range sortedKeys(candidates[tenant]) {
			obs = append(obs, candidates[tenant][k])
		}
		for len(obs) > 0 {
			n := min(len(obs), observationReportMaxPerRecord)
			if !r.write(candidateObservationReportStream, observationReportRecord{Kind: "policy_candidate_observation_report", TenantID: tenant, Observations: obs[:n]}) {
				r.restoreCandidates(tenant, obs)
				break
			}
			obs = obs[n:]
		}
	}
}

func (r *observationReporter) write(stream string, rec observationReportRecord) bool {
	r.mu.Lock()
	seq := r.seq[stream] + 1
	r.mu.Unlock()
	rec.Reporter, rec.Seq = r.reporter, seq
	rec.EventID = fmt.Sprintf("%s:%s:%d", r.reporter, stream, seq)
	rec.Timestamp = r.now().UTC().Format(time.RFC3339)
	if err := r.writer.Append(stream, rec); err != nil {
		log.Printf("observation report: could not write %s for tenant %s (%v); its observations are kept for the next report", stream, rec.TenantID, err)
		return false
	}
	r.mu.Lock()
	r.seq[stream] = seq
	r.mu.Unlock()
	return true
}

func (r *observationReporter) restoreEastWest(tenant string, flows []eastwestobserve.FlowObservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.eastWest[tenant] == nil {
		r.eastWest[tenant] = map[string]eastwestobserve.FlowObservation{}
	}
	for _, f := range flows {
		key := eastwestobserve.ObservationKey(f.Source, f.Destination, f.ServiceFamily, f.Port)
		o, ok := r.eastWest[tenant][key]
		if !ok {
			r.eastWest[tenant][key] = f
			r.pending++
			continue
		}
		o.Count += f.Count
		if f.FirstSeen < o.FirstSeen {
			o.FirstSeen = f.FirstSeen
		}
		if f.LastSeen > o.LastSeen {
			o.LastSeen, o.User = f.LastSeen, f.User
		}
		r.eastWest[tenant][key] = o
	}
}

func (r *observationReporter) restoreCandidates(tenant string, obs []policycandidate.ReportedObservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.candidates[tenant] == nil {
		r.candidates[tenant] = map[string]policycandidate.ReportedObservation{}
	}
	for _, c := range obs {
		key := strings.Join([]string{c.Kind, c.Host, c.SNI, c.ObservedIP, strconv.Itoa(c.Port), c.Reason}, "\x00")
		o, ok := r.candidates[tenant][key]
		if !ok {
			r.candidates[tenant][key] = c
			r.pending++
			continue
		}
		o.Count += c.Count
		if c.LastObserved > o.LastObserved {
			o.LastObserved = c.LastObserved
		}
		r.candidates[tenant][key] = o
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// reportEastWestFlow and reportCandidate are what the traffic path calls. They do nothing on a node that has no
// reporter armed.
func reportEastWestFlow(tenantID, source, user, destination, serviceFamily string, port int, now time.Time) {
	observationReports.Load().eastWestFlow(tenantID, source, user, destination, serviceFamily, port, now)
}

func reportCandidate(kind, tenantID, host, sni, observedIP string, port int, reason string, now time.Time) {
	observationReports.Load().candidate(kind, tenantID, host, sni, observedIP, port, reason, now)
}

// armObservationReports starts reporting on an Edge that ships to a control plane and holds no shared database,
// and returns the reports' shipper so a multi-region control-plane selector can be attached to it. A node with
// the shared database records into it directly and gets nil.
func armObservationReports(writer *logs.Writer, url, token, caFile, certFile, keyFile, logDir string) *remoteAuditShipper {
	if cpStateBlobDB != nil || writer == nil || observationReports.Load() != nil {
		return nil
	}
	shipper, err := newRemoteAuditShipper(url, token, caFile, observationReportStreams, 0,
		filepath.Join(logDir, ".observation_ship", "spool.ndjson"), certFile, keyFile)
	if err != nil {
		log.Fatalf("observation report shipper: %v", err)
	}
	r, err := newObservationReporter(writer)
	if err != nil {
		log.Fatalf("%v", err)
	}
	writer.AddAppendHook(shipper.hook())
	r.shipper = shipper
	r.start()
	observationReports.Store(r)
	log.Printf("observation reports enabled: east-west flows and policy candidates are held by the control plane "+
		"(reporter %s, every %s, streams: %s)", r.reporter, observationReportInterval, strings.Join(observationReportStreams, ", "))
	return shipper
}

// stopObservationReports writes what is waiting and hands it to the shipper's spool, so a SIGTERM loses nothing
// the next process cannot deliver.
func stopObservationReports() {
	r := observationReports.Load()
	if r == nil {
		return
	}
	r.stop()
	r.shipper.stop()
}

// observationReportSink is where a control plane folds reports: its own shared stores.
type observationReportSink struct {
	eastWest   *eastwestobserve.Store
	candidates *policycandidate.Store
}

func isObservationReportStream(stream string) bool {
	return stream == eastWestObservationReportStream || stream == candidateObservationReportStream
}

// applyObservationReport folds one shipped report into the store before the shipment is acknowledged, and
// answers the status the shipper acts on: 400 sets a malformed record aside, 503 keeps it at the head of the
// queue until the store takes it (a standby control plane, a database away), 202 includes a report that was
// already applied.
//
// The receipt is keyed by the shipping certificate's identity as well as the reporter, so an Edge cannot claim
// another Edge's reporter and advance its receipts past reports that have not arrived.
func applyObservationReport(ctx context.Context, sink observationReportSink, stream, shipperIdentity string, body []byte) (int, error) {
	var rec observationReportRecord
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rec); err != nil {
		return http.StatusBadRequest, fmt.Errorf("observation report: %w", err)
	}
	reporter := strings.TrimSpace(shipperIdentity) + "/" + strings.TrimSpace(rec.Reporter)
	if strings.TrimSpace(rec.Reporter) == "" {
		return http.StatusBadRequest, fmt.Errorf("observation report names no reporter")
	}
	now := time.Now()
	var err error
	switch stream {
	case eastWestObservationReportStream:
		if rec.Kind != "east_west_observation_report" || len(rec.Observations) != 0 {
			return http.StatusBadRequest, fmt.Errorf("observation report: %q is not an east-west report", rec.Kind)
		}
		if sink.eastWest == nil {
			return http.StatusServiceUnavailable, fmt.Errorf("this control plane holds no east-west observation store")
		}
		_, err = sink.eastWest.ApplyReport(ctx, rec.TenantID, reporter, rec.Seq, rec.Flows, now)
	case candidateObservationReportStream:
		if rec.Kind != "policy_candidate_observation_report" || len(rec.Flows) != 0 {
			return http.StatusBadRequest, fmt.Errorf("observation report: %q is not a policy candidate report", rec.Kind)
		}
		if sink.candidates == nil {
			return http.StatusServiceUnavailable, fmt.Errorf("this control plane holds no policy candidate store")
		}
		_, err = sink.candidates.ApplyReport(ctx, rec.TenantID, reporter, rec.Seq, rec.Observations, now)
	default:
		return http.StatusBadRequest, fmt.Errorf("not an observation report stream")
	}
	switch {
	case err == nil:
		return http.StatusAccepted, nil
	case errors.Is(err, eastwestobserve.ErrInvalidReport), errors.Is(err, policycandidate.ErrInvalidReport):
		return http.StatusBadRequest, err
	default:
		log.Printf("observation report from %s seq %d (%s) not applied yet: %v", reporter, rec.Seq, stream, err)
		return http.StatusServiceUnavailable, fmt.Errorf("observation report not applied; send it again")
	}
}
