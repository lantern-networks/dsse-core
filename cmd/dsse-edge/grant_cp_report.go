package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
)

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
// a registration is a fact that happens once and must not be lost. Grants are few, small and idempotent:
// sending the whole live set converges after any outage without an outbox to drain, and a report lost to a
// control plane that was briefly away costs one interval rather than a grant. An immediate send on mint keeps
// the held flow from waiting for the next tick.
//
// ★★★ THE STORE IS READ PER REPORT, NOT AT CONSTRUCTION (2026-09-02, caught before it shipped). This
// reporter is started while the Edge's outbound clients are assembled, hundreds of lines before the grant
// store exists — the same ordering theIdPRegistry carries a note about. Taking the pointer at construction
// captured nil, and a reporter holding nil is one that runs forever and reports nothing, with no error
// anywhere.
type grantCPReporter struct {
	url    string
	client *http.Client
	grants func() *grantstore.Store
	logf   func(string, ...interface{})
}

// report sends every live grant this node holds. It never returns an error to the ceremony: a user who has
// just authenticated has done their part, and there is nothing useful they could do with "the control plane
// did not answer".
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
	for _, gr := range store.ListAll() {
		if exp, err := time.Parse(time.RFC3339, gr.ExpiresAt); err == nil && !now.Before(exp) {
			continue
		}
		live = append(live, gr)
	}
	if len(live) == 0 {
		return
	}
	body, err := json.Marshal(struct {
		Grants []grantstore.Grant `json:"grants"`
	}{live})
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		if g.logf != nil {
			g.logf("grant_report_deferred grants=%d error=%q — the control plane did not answer; the next "+
				"reconcile carries them", len(live), err.Error())
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 && g.logf != nil {
		g.logf("grant_report_refused grants=%d status=%d — these grants are held by this node alone, so an "+
			"administrator revoking one elsewhere would not reach them", len(live), resp.StatusCode)
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
