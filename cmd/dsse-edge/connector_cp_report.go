package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// connector_cp_report.go — a connector that joins at an Edge is told to the control plane.
//
// ★★★ WHY THIS EXISTS (2026-08-24, measured on a two-Edge fleet). A connector reaches only an Edge, so its
// registration lands on whichever node the region's door chose — and it went no further. Measured: edge-a held
// one connector, edge-b held another, and the control plane held none.
//
// That is not a cosmetic gap. There is no POST /admin/connectors: a connector is not created by an operator,
// it SELF-REGISTERS and the operator then names it and gives it routes — and both of those are writes the
// Console sends to the CONTROL PLANE. So an authority that never learned about the registration has nothing
// to name and nothing to attach a route to, every screen that reads it shows a deployment with no connectors,
// and it cannot even remove one: DELETE answers 404 for a connector that is plainly running.
//
// ★★ IT IS THE SAME SHAPE AS THE ENROLMENT REPORT NEXT DOOR, DELIBERATELY. Same durable outbox, so a control
// plane that is briefly away costs a retry rather than a connector; same rule that the report never fails the
// caller, because the connector has already been admitted and there is nothing useful it could do with "the
// control plane did not answer".
//
// ★★★ AND THE RECEIVER RECORDS RATHER THAN RE-DECIDES. The enrolment report learned this the hard way on the
// same day: it called the ledger method that TAKES the identity claim, the claim was already taken by the node
// that issued the certificate, and every report was refused. Admission happened at the Edge, with the Site's
// bootstrap secret. This report says where — it does not ask permission again.

// connectorReport is one registration, carried.
type connectorReport struct {
	Registration model.ConnectorRegistration `json:"registration"`
	// TenantID is carried separately so a queued report replays into the organization it belongs to rather
	// than whatever happens to be current at drain time — the same reason the enrolment report carries it.
	TenantID string `json:"tenant_id"`
	QueuedAt string `json:"queued_at,omitempty"`
	// AttachedRegionID, when set, makes this an ATTACHMENT report: the node terminating this connector's
	// tunnel saying which region the connector is currently in.
	//
	// ★★★ THE EDGE IS NOT THE AUTHORITY, AND RECORDING IT LOCALLY REACHED NOBODY (2026-08-26, measured on the
	// deployment the installer generates). The attached region was written into the registry of the node that
	// terminated the tunnel — which on this deployment is the Edge's own in-memory copy, fed FROM the control
	// plane. Every other node went on reading the registered region, the database held nothing, and the one
	// fact that keeps a failed-over connector reachable existed only where it was already known. Same family
	// as the enrolment report next door: what the fleet learns, it learns by telling the authority.
	AttachedRegionID string `json:"attached_region_id,omitempty"`
}

// connectorCPReport is the process-wide reporter, set at start-up when this Edge can reach the control
// plane's machine door. nil means a connector that joins here is known to this node alone — which is said out
// loud at start-up rather than left to be discovered from an empty connector list.
//
// Package-level for the same reason enrolmentCPReport is: the handler that needs it is built in a different
// function from the one that can construct it.
var connectorCPReport *connectorCPReporter

// connectorCPReporter tells the control plane about connectors that registered on this Edge.
type connectorCPReporter struct {
	url        string
	client     *http.Client
	outboxPath string
	logf       func(string, ...interface{})
	mu         sync.Mutex
}

// Report ships one registration. It never returns an error to the registration path.
func (c *connectorCPReporter) Report(rep connectorReport) {
	if c == nil || strings.TrimSpace(c.url) == "" {
		return
	}
	if strings.TrimSpace(rep.QueuedAt) == "" {
		rep.QueuedAt = time.Now().UTC().Format(time.RFC3339)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.post(ctx, rep); err != nil {
		c.queue(rep, err)
		return
	}
	if c.logf != nil {
		c.logf("connector_reported_to_control_plane connector=%q tenant=%q — the authority now names it, so it "+
			"can be given a name and routes", rep.Registration.ID, rep.TenantID)
	}
}

// post makes the one call, on the machine door — the same channel the enrolment report uses, where this Edge
// proves which node it is with the certificate the audit channel presents. A shared bearer is not enough to
// write another organization's connector list.
func (c *connectorCPReporter) post(ctx context.Context, rep connectorReport) error {
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	// The write door of whichever region leads. Same decision as the read path, different address — see
	// controlChannelCurrentDataURL. Against a fixed one, a connector that joined here was known to this node
	// alone for as long as leadership stayed in another region, and every screen reads the authority.
	target := strings.TrimRight(c.url, "/")
	if current := controlChannelCurrentDataURL(); current != "" {
		target = strings.TrimRight(current, "/") + machineDoorPath(c.url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusNotFound {
		// The same rule as the enrolment report: these mean an operator decision this Edge cannot resolve by
		// trying again.
		return errNotRetryable{status: resp.StatusCode}
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("control plane refused the connector report: HTTP %d", resp.StatusCode)
	}
	return nil
}

// queue writes the report to the durable outbox so the obligation outlives this process.
func (c *connectorCPReporter) queue(rep connectorReport, cause error) {
	if isNotRetryable(cause) {
		if c.logf != nil {
			c.logf("★ connector_report_refused connector=%q tenant=%q cause=%q — this connector is registered "+
				"HERE and the control plane will not name it, so it can be given no name and no routes",
				rep.Registration.ID, rep.TenantID, cause.Error())
		}
		return
	}
	if strings.TrimSpace(c.outboxPath) == "" {
		if c.logf != nil {
			c.logf("★ connector_report_lost connector=%q tenant=%q error=%q — no outbox is configured, so this "+
				"registration reached nobody and will not be retried", rep.Registration.ID, rep.TenantID, cause.Error())
		}
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	line, err := json.Marshal(rep)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.outboxPath), 0o700); err != nil && c.logf != nil {
		c.logf("★ connector_report_lost connector=%q outbox_error=%q", rep.Registration.ID, err.Error())
	}
	f, err := os.OpenFile(c.outboxPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		if c.logf != nil {
			c.logf("★ connector_report_lost connector=%q outbox_error=%q", rep.Registration.ID, err.Error())
		}
		return
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil && c.logf != nil {
		c.logf("★ connector_report_lost connector=%q write_error=%q", rep.Registration.ID, err.Error())
	}
}

// drain retries the outbox until it is empty.
func (c *connectorCPReporter) drain(ctx context.Context, every time.Duration) {
	if c == nil || strings.TrimSpace(c.outboxPath) == "" {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
			c.drainOnce(ctx)
		}
	}
}

func (c *connectorCPReporter) drainOnce(ctx context.Context) {
	c.mu.Lock()
	raw, err := os.ReadFile(c.outboxPath)
	c.mu.Unlock()
	if err != nil || len(raw) == 0 {
		return
	}
	kept := []connectorReport{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rep connectorReport
		if uerr := json.Unmarshal([]byte(line), &rep); uerr != nil {
			continue // a line that is not a report is not an obligation
		}
		if perr := c.post(ctx, rep); perr != nil {
			if !isNotRetryable(perr) {
				kept = append(kept, rep)
			}
			continue
		}
		if c.logf != nil {
			c.logf("connector_reported_to_control_plane connector=%q tenant=%q (from the outbox)",
				rep.Registration.ID, rep.TenantID)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(kept) == 0 {
		_ = os.Remove(c.outboxPath)
		return
	}
	var buf bytes.Buffer
	for _, rep := range kept {
		if line, merr := json.Marshal(rep); merr == nil {
			buf.Write(append(line, '\n'))
		}
	}
	_ = os.WriteFile(c.outboxPath, buf.Bytes(), 0o600)
}
