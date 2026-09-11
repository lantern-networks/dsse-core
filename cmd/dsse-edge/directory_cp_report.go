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

// directoryImportReport is one connector-driven import, in the shape the control plane's own import route
// takes, plus the tenant it belongs to.
type directoryImportReport struct {
	Request humanidentity.HumanIdentityDirectoryImportRequest `json:"request"`
	// TenantID is not part of the CP's body — the CP takes the tenant from the caller's admin context. It
	// travels here so a queued report is replayed into the organization it actually came from rather than
	// whichever tenant happens to be current when the outbox drains.
	TenantID string `json:"tenant_id"`
	QueuedAt string `json:"queued_at"`
}

type directoryCPReporter struct {
	url        string
	token      string
	client     *http.Client
	outboxPath string
	logf       func(string, ...interface{})

	mu sync.Mutex
}

// Report carries one import to the control plane, queueing it if the control plane cannot take it now. It
// never returns an error: the caller has already applied the import locally.
func (d *directoryCPReporter) Report(report directoryImportReport) {
	if d == nil || strings.TrimSpace(d.url) == "" {
		return
	}
	if strings.TrimSpace(report.QueuedAt) == "" {
		report.QueuedAt = time.Now().UTC().Format(time.RFC3339)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := d.post(ctx, report); err != nil {
		d.queue(report, err)
		return
	}
	if d.logf != nil {
		d.logf("directory_import_reported_to_control_plane tenant=%q source=%q identities=%d — the authority now "+
			"holds these people, so every other Edge and the Console see them too",
			report.TenantID, report.Request.Source, len(report.Request.Identities))
	}
}

func (d *directoryCPReporter) post(ctx context.Context, report directoryImportReport) error {
	body, err := json.Marshal(report.Request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(d.url, "/")+"/admin/human-identities/import", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	req.Header.Set("content-type", "application/json")
	if tenant := strings.TrimSpace(report.TenantID); tenant != "" {
		req.Header.Set("X-Operate-Tenant", tenant)
	}
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

func (d *directoryCPReporter) queue(report directoryImportReport, cause error) {
	if isNotRetryable(cause) {
		if d.logf != nil {
			d.logf("directory_import_report_refused tenant=%q source=%q: %v — NOT queued; retrying cannot change "+
				"this answer, and the control plane does not hold these people",
				report.TenantID, report.Request.Source, cause)
		}
		return
	}
	if strings.TrimSpace(d.outboxPath) == "" {
		if d.logf != nil {
			d.logf("directory_import_report_lost tenant=%q source=%q: %v — no outbox path, so the control plane "+
				"will not learn about these people", report.TenantID, report.Request.Source, cause)
		}
		return
	}
	line, err := json.Marshal(report)
	if err != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(d.outboxPath), 0o700); err != nil {
		return
	}
	file, err := os.OpenFile(d.outboxPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		if d.logf != nil {
			d.logf("directory_import_report_lost tenant=%q: %v", report.TenantID, err)
		}
		return
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		return
	}
	if d.logf != nil {
		d.logf("directory_import_report_queued tenant=%q source=%q identities=%d: %v — the import is live on this "+
			"Edge and will be carried to the control plane when it answers",
			report.TenantID, report.Request.Source, len(report.Request.Identities), cause)
	}
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
	if err != nil || len(raw) == 0 {
		return
	}
	kept := [][]byte{}
	delivered := 0
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var report directoryImportReport
		if err := json.Unmarshal(line, &report); err != nil {
			// An unreadable line is dropped rather than retried forever; it can never become deliverable.
			if d.logf != nil {
				d.logf("directory_import_report_unreadable: %v — dropped from the outbox", err)
			}
			continue
		}
		if err := d.post(ctx, report); err != nil {
			if isNotRetryable(err) {
				if d.logf != nil {
					d.logf("directory_import_report_refused tenant=%q source=%q: %v — dropped from the outbox",
						report.TenantID, report.Request.Source, err)
				}
				continue
			}
			kept = append(kept, line)
			continue
		}
		delivered++
	}
	if delivered == 0 && len(kept) > 0 {
		return
	}
	if len(kept) == 0 {
		_ = os.Remove(d.outboxPath)
	} else {
		_ = os.WriteFile(d.outboxPath, append(bytes.Join(kept, []byte("\n")), '\n'), 0o600)
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
