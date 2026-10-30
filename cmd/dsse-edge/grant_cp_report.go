package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
)

// The CP bounds each report body to protect its decoder. Split the reconciled
// set by encoded bytes so an otherwise healthy fleet does not stop reporting
// grants as soon as its live set exceeds one request.
const maxGrantReportBodyBytes = 256 << 10

type grantReportBody struct {
	Grants          []json.RawMessage `json:"grants"`
	ProtectedGrants []json.RawMessage `json:"protected_grants,omitempty"`
}

type grantReportBatch struct {
	body      []byte
	protected bool
}

func grantReportBatches(rows []grantstore.Grant) ([]grantReportBatch, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	const envelopeBytes = len(`{"grants":[],"protected_grants":[]}`)
	current := grantReportBody{Grants: []json.RawMessage{}}
	used, count := envelopeBytes, 0
	var batches []grantReportBatch
	flush := func() error {
		body, err := json.Marshal(current)
		if err != nil || len(body) > maxGrantReportBodyBytes {
			return fmt.Errorf("grant report batch cannot be encoded within the receiver limit")
		}
		batches = append(batches, grantReportBatch{body: body, protected: len(current.ProtectedGrants) > 0})
		current = grantReportBody{Grants: []json.RawMessage{}}
		used, count = envelopeBytes, 0
		return nil
	}
	for _, grant := range rows {
		encoded, err := json.Marshal(grant)
		if err != nil || envelopeBytes+len(encoded)+1 > maxGrantReportBodyBytes {
			return nil, fmt.Errorf("grant report row cannot be encoded within the receiver limit")
		}
		if count > 0 && used+len(encoded)+1 > maxGrantReportBodyBytes {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		if grant.RequiresModernReader() {
			current.ProtectedGrants = append(current.ProtectedGrants, encoded)
		} else {
			current.Grants = append(current.Grants, encoded)
		}
		used += len(encoded) + 1
		count++
	}
	if count > 0 {
		if err := flush(); err != nil {
			return nil, err
		}
	}
	return batches, nil
}

// grant_cp_report.go — the grants an Edge minted are told to the control plane, so the fleet holds them.
//
// ★★★ WHY (2026-09-02, found by walking the step-up ceremony on a real device). A grant is minted by
// whichever Edge ran the ceremony, into that process's memory. An Edge restart dropped every grant with
// nothing said; and a region with more than one Edge behind its door — the shape this product scales into —
// can run the ceremony on one node and hold the flow on another, so the user authenticates successfully and
// is held again. The revocation surface already claimed "the store is shared"; it was not, so revoking on one
// node left the grant live everywhere else.
//
// ★★ A PERIODIC RECONCILE, NOT AN OUTBOX. The connector report next door queues each event durably, because
// a registration is a fact that happens once and must not be lost. Grant reports are idempotent: sending the
// live set in receiver-sized batches converges after an outage without an outbox to drain. A failed batch
// stops that attempt and the next tick retries the entire set. An immediate send on mint keeps the held flow
// from waiting for the next tick.
//
// ★★★ THE STORE IS READ PER REPORT, NOT AT CONSTRUCTION (2026-09-02, caught before it shipped). This
// reporter is started while the Edge's outbound clients are assembled, hundreds of lines before the grant
// store exists — the same ordering theIdPRegistry carries a note about. Taking the pointer at construction
// captured nil, and a reporter holding nil is one that runs forever and reports nothing, with no error
// anywhere.
type grantCPReporter struct {
	authorityURL string // fixed management base when no CP selector is configured
	url          string
	client       *http.Client
	grants       func() *grantstore.Store
	logf         func(string, ...interface{})
}

// report sends every live grant this node holds. It never returns an error to the ceremony: a user who has
// just authenticated has done their part, and there is nothing useful they could do with "the control plane
// did not answer". The full-set scan remains a separate scale concern.
func (g *grantCPReporter) report(ctx context.Context) {
	if g == nil || strings.TrimSpace(g.url) == "" || g.grants == nil || g.client == nil {
		return
	}
	store := g.grants()
	if store == nil {
		return // not built yet; the next tick will find it
	}
	now := time.Now().UTC()
	live := make([]grantstore.Grant, 0)
	rows, err := store.ListAllChecked()
	if err != nil {
		if g.logf != nil {
			g.logf("grant_report_deferred: authority unavailable")
		}
		return
	}
	for _, gr := range rows {
		if exp, err := time.Parse(time.RFC3339, gr.ExpiresAt); gr.ReauthenticateAfter == "" && err == nil && !now.Before(exp) {
			continue
		}
		live = append(live, gr)
	}
	if len(live) == 0 {
		return
	}
	batches, err := grantReportBatches(live)
	if err != nil {
		if g.logf != nil {
			g.logf("grant_report_deferred: report cannot be encoded")
		}
		return
	}
	for _, batch := range batches {
		reportURL := g.url
		if batch.protected {
			// A released CP can acknowledge but discard modern-only evidence.
			reportURL = strings.TrimSuffix(g.url, "/grant-report") + "/grant-report-v2"
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, reportURL, bytes.NewReader(batch.body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := g.client.Do(req)
		if err != nil {
			if g.logf != nil {
				g.logf("grant_report_deferred grants=%d error=%q — the next reconcile retries all batches", len(live), err.Error())
			}
			return
		}
		// CP acknowledgements are small JSON documents. Drain bounded output so
		// the next batch can reuse the authenticated transport connection.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			if g.logf != nil {
				g.logf("grant_report_refused grants=%d status=%d — the next reconcile retries all batches", len(live), resp.StatusCode)
			}
			return
		}
	}
}

// reconcile sends the live set now and then on every tick.
func (g *grantCPReporter) reconcile(ctx context.Context, every time.Duration) {
	if g == nil || every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		g.report(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// theGrantStore is this node's grant store, published for the two things that need it after start-up: the
// control plane's config-bundle publisher, and the Edge that applies that bundle. Same reason as
// theIdPRegistry beside it — the store is built long after the configuration that reaches those callers.
var theGrantStore atomic.Pointer[grantstore.Store]
