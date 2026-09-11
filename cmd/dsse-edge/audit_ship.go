package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

// Audit/persistence decoupling (docs/edge_audit_persistence_decoupling_design.md): the Edge keeps writing
// audit/events to its local append-only jsonl (canonical, durable-on-the-Edge), AND ships those records to the
// separate audit/control plane's ingest endpoint. The Edge owns no database; the control plane owns Postgres
// persistence. Shipping NEVER blocks enforcement.
//
// Cross-region durability (docs/cross_region_control_plane_failover_design.md, Phase 2): on a CP outage the
// shipper RETAINS un-acked records in a bounded pending spool and REPLAYS them when a CP is reachable again —
// including after an Edge→CP region failover (it ships to the current leader via the same cp_endpoint_failover
// selector). Ingest is idempotent by (tenant, stream, event_id) on every hot-store backend — Postgres upserts ON
// CONFLICT; ClickHouse sets an insert_deduplication_token — so a replay never double-counts. Only when the bounded
// spool overflows are the oldest records dropped — logged, never silent (the local jsonl still holds them).

// defaultAuditShipStreams are the log streams shipped to the control plane by default (audit + access, plus
// device_state so the control plane's Postgres holds device-state CHANGE history for the GUI to read — the Edge
// stays zero-DB and decoupled).
//
// inspection_events carries the DLP findings + SWG inspection outcomes. It is shipped so the DLP-Findings view
// reads the AGGREGATED, fleet-wide, restart-safe hot store (event_log_design.md, S2) instead of a single
// Edge's in-memory cache. NOTE: under decrypt-all + log-all this is high volume; the shipper's bounded buffer
// drops oldest under backpressure (never OOMs the Edge), and cardinality control (rollup/sample, design/S4)
// must land before production scale so the CP is not fire-hosed with one row per flow.
// config_generations MUST ship wherever access.log ships: an access record carries only a config_generation_id,
// so a control plane that has the record but not the generation row holds an unresolvable reference — the record
// would lose exactly the "which config was in force" property the normalisation exists to preserve (a).
// Adding a stream here also requires adding it to the Console's _LA_SHIPPED_STREAMS, or its tab reads the edge.
var defaultAuditShipStreams = []string{"audit.log.jsonl", "access.log.jsonl", "device_state.log.jsonl",
	"inspection_events.log.jsonl", "config_generations.log.jsonl",
	// Each device's own account of what it is applying — reverse telemetry. Added 2026-08-23 so the durable
	// copy lives on the control plane instead of the Edge writing it into Postgres itself. See
	// observed_exclusion_ship.go.
	observedExclusionShipStream,
	// Which certificate each device is actually presenting. Shipped since 2026-08-23 so the device-CA
	// withdrawal gate can answer from the FLEET rather than from whichever node happens to be asked — a
	// control plane sees no handshakes at all, and could not withdraw a CA it had itself registered.
	deviceCertificateFactStream}

type auditShipItem struct {
	stream string
	record []byte
}

type remoteAuditShipper struct {
	url string // full ingest URL (single-CP fallback), e.g. https://cp:9443/audit-ingest
	// endpoints, when set (multi-region CP), gives the current healthy CP admin base; the ingest URL is
	// base + "/audit-ingest". "" = no in-boundary CP → retain + retry. See cp_endpoint_failover.go. Held as an
	// atomic pointer because it is wired in AFTER construction (the CP selector is built later in main), while
	// run may already be reading it.
	endpoints   atomic.Pointer[cpEndpointSelector]
	token       string
	client      *http.Client
	streams     map[string]bool
	ch          chan auditShipItem
	maxPending  int             // bounded pending spool; overflow drops the oldest (logged)
	spool       *shipSpool      // durable, restart-surviving mirror of the pending queue (nil = in-memory only)
	spoolReplay []auditShipItem // un-acked records recovered from the spool at startup, seeded into run's queue
	pending     atomic.Int64    // current un-acked count (observability)
	dropped     atomic.Int64
	failed      atomic.Int64
	shipped     atomic.Int64
	// refused counts records the control plane will never accept. They are NOT dropped: each one is written
	// to deadSpool first, because "the receiver refuses this" and "this never happened" are different facts
	// and only one of them is true.
	refused   atomic.Int64
	deadSpool *shipSpool
	// ★★★ WHAT IS FAILING, SOMEWHERE A DEPLOYMENT CAN READ IT (2026-08-24). This condition existed only as a
	// line on the node's own stdout: an Edge whose history was reaching nobody said so once, in a log, and no
	// screen, no health check and no installer check could tell. That is the shape of every silent failure
	// this repository has paid for — the node knows, and the deployment does not. These two are reported on
	// /healthz, which is what the front door polls and what -verify reads.
	failingSinceUnix atomic.Int64
	lastError        atomic.Pointer[string]
	// quit ends run, which is what lets its deferred compact+close of the durable spool actually happen.
	// Without it the goroutine started in the constructor could only end with the process, so the spool file
	// handle was released by exit rather than by the code that opens it. A separate channel rather than closing
	// ch: hook sends on ch from the log path, and closing a channel someone may still send on is a panic.
	quit     chan struct{}
	quitOnce sync.Once
	done     chan struct{} // closed by run on its way out, after the spool is compacted and closed
}

// stop ends the shipping goroutine and WAITS for it, so that when this returns the spool has been compacted to
// the un-acked set and its file handle released. Signalling without waiting would make "stopped" mean "asked to
// stop", and a caller that then reads or removes the spool would be racing the goroutine still writing it.
// Safe to call more than once, and safe to call on a shipper whose run has already returned.
func (s *remoteAuditShipper) stop() {
	if s == nil {
		return
	}
	s.quitOnce.Do(func() { close(s.quit) })
	<-s.done
}

// baseURL is the full ingest URL to POST to now: the current healthy CP's admin base + /audit-ingest when region
// failover is configured, else the fixed single-CP URL. "" = no in-boundary CP reachable → retain + retry.
func (s *remoteAuditShipper) baseURL() string {
	if ep := s.endpoints.Load(); ep != nil {
		base := ep.CurrentBaseURL()
		if strings.TrimSpace(base) == "" {
			return ""
		}
		return strings.TrimRight(base, "/") + "/audit-ingest"
	}
	return s.url
}

// setEndpoints wires the multi-region CP selector so audit replay follows the current CP leader after an Edge→CP
// region failover. Called once during startup; safe against the running ship loop (atomic).
func (s *remoteAuditShipper) setEndpoints(ep *cpEndpointSelector) {
	if s == nil || ep == nil {
		return
	}
	s.endpoints.Store(ep)
}

// newRemoteAuditShipper builds a best-effort shipper to the control-plane ingest URL. caPEMFile (optional)
// pins the ingest endpoint's CA; empty uses the system roots. bufSize bounds the in-flight queue. spoolPath
// (optional) is the durable, restart-surviving spool file for the un-acked queue — empty keeps it in-memory only
// (an Edge restart then drops in-flight records; the canonical jsonl still holds them but nothing resumes).
func newRemoteAuditShipper(url, token, caPEMFile string, streams []string, bufSize int, spoolPath string,
	clientCertFile, clientKeyFile string) (*remoteAuditShipper, error) {
	// url may be empty when the shipper is driven purely by a multi-region CP selector (setEndpoints); the caller
	// guarantees at least one target (fixed url and/or endpoints). With neither, baseURL=="" → records are
	// retained + retried forever (bounded spool, oldest-dropped-logged) — a misconfiguration, not silent loss.
	url = strings.TrimSpace(url)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if p := strings.TrimSpace(caPEMFile); p != "" {
		pem, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read audit ingest CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("audit ingest CA file contained no usable certificates")
		}
		tlsCfg.RootCAs = pool
	}
	// ★ THE SHIPPER PRESENTS ITS OWN CERTIFICATE (2026-08-12, tenth review). The receiver was taught to derive
	// the sending Edge's tenant from the certificate it presents and to refuse a record naming another — and
	// this side sent NONE, so that check reached its "cannot verify" branch on every real shipment and the
	// shared bearer was the only control after all. A binding that never engages is worse than no binding: it
	// reads as closed.
	if cert, key := strings.TrimSpace(clientCertFile), strings.TrimSpace(clientKeyFile); cert != "" && key != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("read the audit-ingest client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	} else {
		// ★ THIS IS PROBABLY FATAL, NOT MERELY WEAKER (2026-08-14). The wording here used to stop at "the shared
		// bearer is then the only control", which reads as a hardening note — and region-b, configured with the
		// url and token but not these two flags, printed it once and then retained everything it produced for an
		// afternoon. A receiver that derives shippable tenants from the presented certificate (ours does)
		// answers 401 to a bearer alone, so this is the difference between shipping and not shipping at all.
		log.Printf("★ audit shipping has NO client certificate (-audit-ingest-client-cert/-key): a control plane " +
			"that binds records to the presenting edge will answer 401 and NOTHING WILL SHIP — records will be " +
			"retained and retried indefinitely. Even where it is accepted, the shared bearer is then the only " +
			"control on which tenant's history they may write")
	}
	if bufSize <= 0 {
		bufSize = 4096
	}
	set := map[string]bool{}
	for _, s := range streams {
		if s = strings.TrimSpace(s); s != "" {
			set[s] = true
		}
	}
	spool, replay, err := newShipSpool(spoolPath, bufSize)
	if err != nil {
		return nil, err
	}
	// Beside the pending spool, and only ever appended to: the records the control plane refused for good.
	// A separate file because the two answer different questions — "what has not been delivered yet" and
	// "what will never be delivered" — and because a dead record must not be replayed by the ordinary restart
	// path, which would put the queue straight back where it was.
	var deadSpool *shipSpool
	if strings.TrimSpace(spoolPath) != "" {
		// The recovered set is deliberately discarded: this file is a record, not a queue.
		deadSpool, _, err = newShipSpool(spoolPath+".refused", bufSize)
		if err != nil {
			return nil, err
		}
	}
	s := &remoteAuditShipper{
		url:         url,
		token:       strings.TrimSpace(token),
		client:      &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
		streams:     set,
		ch:          make(chan auditShipItem, bufSize),
		maxPending:  bufSize,
		spool:       spool,
		deadSpool:   deadSpool,
		spoolReplay: replay,
		quit:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	go s.run()
	return s, nil
}

// hook returns a logs.AppendHook that enqueues matching records for shipping. It copies the encoded bytes
// (the writer reuses its buffer) and NEVER blocks or errors — enforcement must not depend on the ship path.
func (s *remoteAuditShipper) hook() logs.AppendHook {
	return func(filename string, encoded []byte) error {
		if s == nil || !s.streams[filename] {
			return nil
		}
		rec := append([]byte(nil), encoded...)
		select {
		case s.ch <- auditShipItem{stream: filename, record: rec}:
		default:
			s.dropped.Add(1) // best-effort: the local jsonl is the durable fallback
		}
		return nil
	}
}

// run drains new records into a bounded FIFO pending spool and ships the head, RETAINING un-acked records on
// failure and retrying with backoff (so a CP outage / region failover loses nothing within the spool window).
func (s *remoteAuditShipper) run() {
	defer close(s.done)
	// Seed the queue from the durable spool: un-acked records that were in flight when the Edge last stopped are
	// re-shipped instead of lost (idempotent ingest makes the replay safe). Trim to the queue cap if the recovered
	// set is larger, dropping the oldest.
	q := s.spoolReplay
	s.spoolReplay = nil
	if len(q) > s.maxPending {
		over := len(q) - s.maxPending
		q = append([]auditShipItem(nil), q[over:]...)
		s.dropped.Add(int64(over))
	}
	if len(q) > 0 {
		s.pending.Store(int64(len(q)))
		s.spool.compact(q) // rewrite the spool to exactly the recovered set (drops any trimmed/acked leftovers)
		log.Printf("audit ship: replayed %d un-acked record(s) from the durable spool", len(q))
	}
	// Shutdown: leave the spool == the un-acked set, and release BOTH handles.
	//
	// ★ THE REFUSED SPOOL WAS OPENED AND NEVER CLOSED (2026-08-17, found on win-dev-1). Only s.spool was
	// released here, so the append handle on <spool>.refused leaked for the life of the process. On POSIX that
	// is invisible — an open file still unlinks — which is why every macOS run was green. On Windows an open
	// handle means the file cannot be renamed or removed AT ALL, so the record of what the control plane
	// refused could never be rotated or cleared while the Edge was running, and four tests failed in cleanup
	// with "The process cannot access the file because it is being used by another process".
	//
	// It is the same family as the audit spool that could never compact because it renamed a file it still
	// held open — the one this component already learned from. close() is nil-safe, so this is correct when no
	// spool path is configured and deadSpool is nil.
	defer func() { s.spool.compact(q); s.spool.close(); s.deadSpool.close() }()
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	// How often to repeat "still failing" while shipping is down. Long enough that a CP restart does not
	// produce a paragraph, short enough that an operator scrolling a log cannot miss an outage in progress.
	const failLogEvery = 5 * time.Minute
	var failingSince, lastFailLog time.Time
	// The shipped count at the moment the current head first came back with a record-specific refusal, or -1
	// when no such refusal is outstanding. If the count MOVES while a record keeps being refused, the channel
	// works and the record is the problem.
	shippedWhenHeadFirstRefused := int64(-1)
	// How many times the head has been rotated to the back since anything last shipped. Bounded by the queue
	// length: one pass is the experiment, and a second would be the same question asked twice.
	rotationsSinceProgress := 0
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	armed := false
	enqueue := func(item auditShipItem) {
		q = append(q, item)
		s.spool.append(item) // durable BEFORE we ever attempt to ship it
		if len(q) > s.maxPending {
			over := len(q) - s.maxPending
			q = append([]auditShipItem(nil), q[over:]...) // drop the oldest un-shipped
			s.dropped.Add(int64(over))
			log.Printf("audit ship: pending spool full (max %d) — dropped %d oldest un-shipped record(s); the local jsonl still holds them", s.maxPending, over)
			s.spool.compact(q) // drop them from disk too, keeping the spool == the queue
		} else {
			s.spool.maybeCompact(q)
		}
		s.pending.Store(int64(len(q)))
	}
	for {
		// Absorb any queued new records without blocking.
		drained := false
		for !drained {
			select {
			case item, ok := <-s.ch:
				if !ok {
					return
				}
				enqueue(item)
			default:
				drained = true
			}
		}
		if len(q) == 0 {
			select {
			case item, ok := <-s.ch: // nothing pending → block for the next record
				if !ok {
					return
				}
				enqueue(item)
			case <-s.quit:
				return
			}
			continue
		}
		if armed { // in backoff after a failure: wait for the timer OR a new record
			select {
			case item, ok := <-s.ch:
				if !ok {
					return
				}
				enqueue(item)
				continue
			case <-timer.C:
				armed = false
			case <-s.quit:
				return
			}
		}
		if err := s.ship(q[0]); err != nil {
			// ★ A REFUSAL THAT WILL NEVER SUCCEED MUST NOT HOLD THE QUEUE (2026-08-16). Set the record aside
			// durably, say so, and carry on with the next one. Two facts have to stay separate: the receiver
			// refuses THIS record, and every other record is still deliverable. Retrying the first forever
			// makes the second untrue — the lab shipped nothing for two days over one organization's records.
			//
			// Set aside, never dropped. The local jsonl still holds it and so does the dead spool, so the
			// answer to "what did the control plane never accept" is a file rather than an inference.
			var refusal auditShipRefusal
			// ★ IS THIS REFUSAL ABOUT THE RECORD, OR ABOUT THE CHANNEL? A status code cannot say, so the
			// shipper runs the experiment rather than guessing: rotate the head to the back, try the next
			// one, and watch whether ANYTHING gets through. If something does, the receiver is willing and it
			// is this record it will not take. If nothing does, the channel is down — which is what region-b
			// looked like for two days on a 401, and where retaining every record is exactly right.
			//
			// Two bounds, each of which this code was written without and then failed on:
			//   - one pass around the queue, or the loop spins with no backoff, hammering a receiver that is
			//     already saying no (a test run took 600 seconds and was killed);
			//   - the watermark is recorded BEFORE it is compared, or the first refusal reads the sentinel as
			//     "something shipped since" and sets the record aside immediately — the
			//     misconfiguration-as-bad-records mistake this whole design exists to avoid.
			if errors.As(err, &refusal) && refusal.recordSpecific() {
				if shippedWhenHeadFirstRefused < 0 {
					shippedWhenHeadFirstRefused = s.shipped.Load()
				} else if s.shipped.Load() > shippedWhenHeadFirstRefused {
					// The evidence is in. Set it aside — durably, never dropped — and stop it holding
					// everybody else's history. Queue length does not matter here: what matters is that other
					// records went through while this one kept coming back.
					dead := q[0]
					if s.deadSpool != nil {
						s.deadSpool.append(dead)
					}
					s.refused.Add(1)
					q = q[1:]
					// ★ DURABLE FIRST, THEN THE COUNTER — the invariant stated at the drain below is that
					// pending==0 implies the spool is compacted, and this path had it the other way round.
					// Setting aside the LAST queued record made pending==0 while the spool still held it, so
					// a reader trusting the invariant saw a drained queue backed by a spool that was not, and
					// a restart in that window replayed a record already set aside.
					s.spool.compact(q)
					s.pending.Store(int64(len(q)))
					log.Printf("★ audit ship: SET ASIDE — %v (stream %q). Other records are being accepted, so "+
						"the control plane is refusing THIS one and will keep refusing it. It has been written "+
						"to the refused spool (%d so far) and the queue continues; nothing was discarded and "+
						"the local jsonl still holds it. A 403 here usually means this Edge is not authorised "+
						"to ship for that record's organization (-audit-ingest-authority on the control plane).",
						err, dead.stream, s.refused.Load())
					shippedWhenHeadFirstRefused = -1
					rotationsSinceProgress = 0
					continue
				}
				if len(q) > 1 && rotationsSinceProgress < len(q) {
					rotationsSinceProgress++
					q = append(q[1:], q[0])
					s.spool.compact(q)
					continue
				}
				// Every record has been offered and none went through. That IS the channel being down, so
				// fall through to the ordinary retain-and-back-off path below.
			}
			s.failed.Add(1)
			// ★ SAY SO (2026-08-14). This incremented a counter and went back to sleep. An Edge could retain
			// every record it produced, forever, without writing one line about it — which is what region-b did:
			// 176 records held for an afternoon (the Mac's steering among them) because it had been given the
			// ingest URL and token but not the client certificate the receiver requires, and the only line it
			// ever printed said the missing certificate weakened tenant binding. It does not weaken it; the
			// receiver answers 401 and nothing ships. "Retaining safely" and "cannot ship at all" were the same
			// silence, and the retain-and-replay design is exactly what makes that silence survivable enough to
			// last an afternoon.
			//
			// Logged on the EDGES of the condition plus a slow heartbeat while it persists: the first failure
			// with its error, then at most once every failLogEvery, then recovery. Not once per attempt — the
			// backoff already retries hard, and a line per attempt is how a log gets ignored.
			now := time.Now()
			msg := err.Error()
			s.lastError.Store(&msg)
			if failingSince.IsZero() {
				failingSince = now
				lastFailLog = now
				s.failingSinceUnix.Store(now.Unix())
				log.Printf("★ audit ship: FAILING — %v (%d record(s) pending, retained and retried; nothing is "+
					"lost yet, but no history is reaching the control plane)", err, len(q))
			} else if now.Sub(lastFailLog) >= failLogEvery {
				lastFailLog = now
				log.Printf("★ audit ship: still failing after %s — %v (%d record(s) pending)",
					now.Sub(failingSince).Truncate(time.Second), err, len(q))
			}
			timer.Reset(backoff)
			armed = true
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}
		// ★ THE WATERMARK IS NOT RESET HERE, AND THAT WAS THE LAST THING TO GET RIGHT. Clearing it on every
		// success erases the evidence it exists to hold: after the deliverable records drained, the refused
		// one was alone in the queue, its watermark had been wiped, and no further success could ever occur
		// to prove the channel — so it retried forever and was never set aside. Left standing, it says "the
		// channel has worked since this refusal started", which is exactly the question.
		rotationsSinceProgress = 0
		if !failingSince.IsZero() {
			log.Printf("audit ship: recovered after %s — draining %d retained record(s)",
				time.Since(failingSince).Truncate(time.Second), len(q))
			failingSince = time.Time{}
			s.failingSinceUnix.Store(0)
			s.lastError.Store(nil)
		}
		s.shipped.Add(1)
		q = q[1:]
		if len(q) == 0 {
			s.spool.compact(q) // fully drained → clear the durable spool
		} else {
			s.spool.maybeCompact(q) // periodically drop the acked prefix from disk
		}
		s.pending.Store(int64(len(q))) // after the durable update, so pending==0 implies the spool is compacted
		backoff = time.Second
	}
}

func (s *remoteAuditShipper) ship(item auditShipItem) error {
	url := s.baseURL()
	if strings.TrimSpace(url) == "" {
		return fmt.Errorf("no in-boundary control plane reachable (retaining audit record)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(item.record))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-audit-stream", item.stream)
	if s.token != "" {
		req.Header.Set("authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return auditShipRefusal{status: resp.StatusCode}
	}
	return nil
}

// auditShipRefusal is a non-2xx answer from the ingest endpoint, carrying whether retrying could ever help.
type auditShipRefusal struct{ status int }

func (e auditShipRefusal) Error() string {
	return fmt.Sprintf("audit ingest returned HTTP %d", e.status)
}

// recordSpecific reports whether this refusal could be ABOUT THIS RECORD rather than about the channel.
//
// ★ AND THE STATUS CODE ALONE CANNOT ANSWER IT (2026-08-16). The first version read "4xx = permanent", which
// an existing test immediately refuted: region-b was answered 401 for TWO DAYS because it had the ingest URL
// and token but not the client certificate — a channel problem where nothing at all was deliverable, and
// where retaining every record was exactly right. Setting those aside would have turned a fixable
// misconfiguration into a pile of records nobody would ever replay.
//
// So the code narrows the suspects and the SHIPPER RUNS THE EXPERIMENT (see run): a record-specific refusal
// is one where the channel demonstrably works for other records. 408 and 429 are excluded outright — they
// are the server asking for the same bytes later, which is what the retry loop is for — and so is 5xx, where
// the receiver is unwell rather than the record wrong.
func (e auditShipRefusal) recordSpecific() bool {
	switch e.status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return e.status >= 400 && e.status < 500
}

// health is what this node says about whether its history is reaching the authority.
//
// ★ "delivering" IS NOT "pending == 0". A node that has shipped nothing because it has recorded nothing has an
// empty queue and a perfectly healthy channel; a node that is failing also drains to zero the moment the
// receiver comes back. What distinguishes them is whether a failure is CURRENTLY standing, which is what
// failing_since holds.
func (s *remoteAuditShipper) health(now time.Time) map[string]any {
	if s == nil {
		return map[string]any{"configured": false}
	}
	out := map[string]any{
		"configured": true,
		"endpoint":   s.baseURL(),
		"pending":    s.pending.Load(),
		"shipped":    s.shipped.Load(),
		"failed":     s.failed.Load(),
		"dropped":    s.dropped.Load(),
		// refused records are set aside rather than lost: "the receiver refuses this" and "this never
		// happened" are different facts and only one of them is true.
		"refused":    s.refused.Load(),
		"delivering": true,
	}
	if since := s.failingSinceUnix.Load(); since > 0 {
		out["delivering"] = false
		out["failing_since"] = time.Unix(since, 0).UTC().Format(time.RFC3339)
		out["failing_for_seconds"] = int64(now.Sub(time.Unix(since, 0)).Seconds())
	}
	if e := s.lastError.Load(); e != nil {
		out["last_error"] = *e
	}
	return out
}
