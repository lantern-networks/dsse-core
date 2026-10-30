package main

// directory_cp_report.go — a directory import that arrives at an Edge is carried to the control plane.
//
// ★ WHY THIS EXISTS (2026-08-19). The people directory is authored on the control plane and distributed to
// the Edges in the config bundle. But a CONNECTOR lives inside the customer's own network and reaches the
// Edge and nothing else — it cannot be pointed at the control plane. So the one channel a customer has for
// syncing their directory from their IdP arrives at the node that is NOT the authority.
//
// Refusing it, which this Edge briefly did, takes the channel away. Accepting it and stopping there leaves
// two answers to "who works at this organization": the one the connector wrote to this node, and the one the
// control plane holds and hands to every other Edge, the Console and the seat count. Relaying is the only
// answer that keeps both the channel and the authority.
//
// ★ IT IS DURABLE, NOT BEST-EFFORT, for the same reason enrolment's report is: the retry cannot come from
// the sender. A connector that has already been told its import succeeded moves its checkpoint forward and
// will not send those records again, so a report dropped here is a set of people the control plane never
// learns about until the source is resynced from scratch.
//
// ★ IT DOES NOT FAIL THE IMPORT. The identities are already in this Edge's directory and already enforcing;
// a control plane that is briefly away must not turn a successful sync into an error the connector reports
// as a broken integration.

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

	humanidentity "github.com/lantern-networks/dsse-core/humanidentity"
)

// directoryImportReport is one connector-driven import, with the tenant and
// connector identity the authority must independently verify.
type directoryImportReport struct {
	Request humanidentity.HumanIdentityDirectoryImportRequest `json:"request"`
	// TenantID is a claim until the CP checks the reporting Edge certificate,
	// connector registration and source assignment.
	TenantID string `json:"tenant_id"`
	// ConnectorID is checked again by the control plane against its own
	// registration and source policy; a report cannot claim a different source.
	ConnectorID string `json:"connector_id"`
	QueuedAt    string `json:"queued_at"`
}

type directoryCPReporter struct {
	// url is the machine-door base URL, using the verified Edge mTLS client.
	url        string
	client     *http.Client
	outboxPath string
	logf       func(string, ...interface{})

	mu sync.Mutex
}

// Report carries one import to the control plane. A temporary outage may be
// acknowledged only after the report is durable in the local outbox; otherwise
// the connector must not advance its checkpoint.
func (d *directoryCPReporter) Report(report directoryImportReport) error {
	if d == nil || strings.TrimSpace(d.url) == "" {
		return fmt.Errorf("directory machine report channel is unavailable")
	}
	if strings.TrimSpace(report.QueuedAt) == "" {
		report.QueuedAt = time.Now().UTC().Format(time.RFC3339)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := d.post(ctx, report); err != nil {
		if queueErr := d.queue(report, err); queueErr != nil {
			return queueErr
		}
		// A content/route refusal can require an operator correction. Keep the
		// outbox obligation but do not tell the connector it may checkpoint.
		if isNotRetryable(err) {
			return err
		}
		return nil
	}
	if d.logf != nil {
		d.logf("directory_import_reported_to_control_plane tenant=%q source=%q identities=%d — the authority now "+
			"holds these people, so every other Edge and the Console see them too",
			report.TenantID, report.Request.Source, len(report.Request.Identities))
	}
	return nil
}

func (d *directoryCPReporter) post(ctx context.Context, report directoryImportReport) error {
	if d.client == nil || strings.TrimSpace(d.url) == "" {
		return fmt.Errorf("directory machine report channel is not configured")
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	base := strings.TrimRight(d.url, "/")
	if current := controlChannelCurrentDataURL(); current != "" {
		base = strings.TrimRight(current, "/")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/directory-import-report", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// A 400 is the control plane rejecting the CONTENT, and replaying it produces the same 400 for as long as
	// the outbox lives. 404 means the route is not there to talk to. Neither is fixed by trying again.
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound {
		return errNotRetryable{status: resp.StatusCode}
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("control plane refused the directory import: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (d *directoryCPReporter) queue(report directoryImportReport, cause error) error {
	if strings.TrimSpace(d.outboxPath) == "" {
		if d.logf != nil {
			d.logf("directory_import_report_lost tenant=%q source=%q: %v — no outbox path, so the control plane "+
				"will not learn about these people", report.TenantID, report.Request.Source, cause)
		}
		return fmt.Errorf("directory report has no durable outbox: %w", cause)
	}
	line, err := json.Marshal(report)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := appendCPReportOutbox(d.outboxPath, line); err != nil {
		if d.logf != nil {
			d.logf("directory_import_report_lost tenant=%q: %v", report.TenantID, err)
		}
		return fmt.Errorf("directory report outbox append failed: %w", err)
	}
	if d.logf != nil {
		d.logf("directory_import_report_queued tenant=%q source=%q identities=%d: %v — the import is live on this "+
			"Edge and will be carried to the control plane when it answers",
			report.TenantID, report.Request.Source, len(report.Request.Identities), cause)
	}
	return nil
}

func (d *directoryCPReporter) drain(ctx context.Context, every time.Duration) {
	if d == nil || strings.TrimSpace(d.outboxPath) == "" {
		return
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.drainOnce(ctx)
		}
	}
}

func (d *directoryCPReporter) drainOnce(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	raw, err := os.ReadFile(d.outboxPath)
	if err != nil {
		if !os.IsNotExist(err) && d.logf != nil {
			d.logf("directory_import_report_outbox_read_failed: %v — replay stopped; original outbox preserved", err)
		}
		return
	}
	if len(raw) == 0 {
		return
	}
	type queued struct {
		line   []byte
		report directoryImportReport
	}
	var pending []queued
	// Validate the complete snapshot before sending any report. A bad interior
	// line or torn tail is an unresolved obligation, not permission to drop it.
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var report directoryImportReport
		if err := decodeCPReportObject(line, &report); err != nil {
			if d.logf != nil {
				d.logf("directory_import_report_outbox_unreadable: %v — replay stopped; original outbox preserved", err)
			}
			return
		}
		pending = append(pending, queued{line: line, report: report})
	}
	kept := [][]byte{}
	delivered := 0
	for _, item := range pending {
		line, report := item.line, item.report
		if err := d.post(ctx, report); err != nil {
			if isNotRetryable(err) && d.logf != nil {
				d.logf("directory_import_report_refused tenant=%q source=%q: %v — kept for operator correction",
					report.TenantID, report.Request.Source, err)
			}
			kept = append(kept, line)
			continue
		}
		delivered++
	}
	if delivered == 0 && len(kept) > 0 {
		return
	}
	var remaining []byte
	if len(kept) > 0 {
		remaining = append(bytes.Join(kept, []byte("\n")), '\n')
	}
	if err := replaceCPReportOutbox(d.outboxPath, remaining); err != nil {
		if d.logf != nil {
			d.logf("directory_import_report_outbox_rewrite_failed: %v — original outbox retained or durability unconfirmed", err)
		}
		return
	}
	if delivered > 0 && d.logf != nil {
		d.logf("directory_import_outbox_drained delivered=%d still_queued=%d", delivered, len(kept))
	}
}

// directoryImportOutboxPath mirrors enrolmentOutboxPath: the state dir when there is one, the log dir
// otherwise, because the log dir is always set and always durable.
func directoryImportOutboxPath(stateDir, logDir string) string {
	if path := strings.TrimSpace(durableStorePath(stateDir, "", "directory_import_outbox")); path != "" {
		return path
	}
	if dir := strings.TrimSpace(logDir); dir != "" {
		return filepath.Join(dir, "directory_import_outbox.jsonl")
	}
	return ""
}
