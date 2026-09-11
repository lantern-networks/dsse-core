package main

// enrolment_cp_report.go — an enrolment that happens on an Edge is told to the control plane.
//
// ★ WHY THIS EXISTS (2026-08-15). POST /enroll wrote to the Edge's own ledger and nowhere else, and the
// config bundle rebuilds that ledger from the control plane's copy. So on any Edge that follows a control
// plane — which is now every deployed Edge, since one without a control plane refuses to start — a device
// that enrolled here was named by nobody in the CP's inventory and was DROPPED from admission on the next
// bundle. It kept a valid certificate and was refused at the transport handshake, which reads as a PKI or
// transport fault and sends the investigation to the wrong place entirely.
//
// The ledger already said so out loud (enrolledinventory.MergeAuthoritative logs the drop by name), and this
// is the other half of that sentence: the report that stops it being true. It was observed live on
// 2026-08-15, on the Windows transport lab Edge the moment it was given a control plane — conn-lab-1 had
// enrolled there, the CP had never heard of it, and it was dropped.
//
// ★ IT IS DURABLE, NOT BEST-EFFORT, AND THAT IS THE WHOLE DESIGN. The neighbouring Edge→CP reporter
// (fleetConfigReporter) is deliberately best-effort: losing a status report costs visibility until the next
// one. Losing THIS report costs the device its admission at the next bundle, silently and permanently — the
// retry would have to come from the device enrolling again, which it cannot do, because enrolment is
// one-time by construction. So a report that cannot be delivered now is written to a durable outbox and
// retried until the control plane takes it.
//
// ★ IT DOES NOT FAIL THE ENROLMENT. A control plane that is briefly unreachable must not strand a machine an
// operator has already approved — fifty laptops being kitted while the CP restarts is an ordinary morning,
// not an incident. The device gets its certificate; the outbox carries the obligation.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// enrolmentReport is one enrolment this Edge completed, in the shape POST /admin/enrolled-devices takes.
type enrolmentReport struct {
	Identity string `json:"identity"`
	Group    string `json:"group,omitempty"`
	Note     string `json:"note,omitempty"`
	// TenantID is NOT part of the CP's request body — the CP takes the tenant from the caller's admin
	// context. It is carried here so the outbox can replay the report with the right X-Operate-Tenant, and
	// so a queued report cannot be replayed into whatever tenant happens to be current at drain time.
	TenantID string `json:"tenant_id"`
	// MachineRef is what the agent said about the machine, carried so the AUTHORITY holds it. Without this the
	// value lives only on the Edge that issued the certificate, and the next config bundle — which replaces
	// the ledger from the control plane's copy — erases it. See enrolledinventory.Entry.MachineRef.
	MachineRef string `json:"machine_ref,omitempty"`
	// QueuedAt exists for the operator reading the outbox, not for the CP: "how long has this been stuck".
	QueuedAt string `json:"queued_at"`
}

// enrolmentCPReporter tells the control plane about enrolments completed on this Edge.
type enrolmentCPReporter struct {
	url        string
	token      string
	client     *http.Client
	outboxPath string
	logf       func(string, ...interface{})
	// machineURL and machineClient are the MACHINE door, where this Edge proves which node it is with the
	// same certificate the material fetch presents.
	//
	// ★★★ THE ADMIN DOOR CANNOT CARRY A CROSS-ORGANIZATION REPORT (2026-08-21, measured on the first one).
	// Reporting through /admin/enrolled-devices with an operator bearer and X-Operate-Tenant answered 403:
	// crossing into another organization needs a time-boxed elevation and a machine holds none. The outbox
	// queued it, correctly, and it would have queued forever. See registerEnrolmentReportRoute — an Edge
	// recording where a device enrolled is not an operator acting on a customer.
	machineURL    string
	machineClient *http.Client

	mu sync.Mutex // serialises outbox read-modify-write against concurrent enrolments and the drain loop
}

// Report ships one enrolment. It never returns an error to the enrolment path: the caller has already issued
// a certificate, and there is no useful way for a device to react to "the control plane did not answer".
// What it guarantees instead is that the obligation is not lost.
func (e *enrolmentCPReporter) Report(rep enrolmentReport) {
	if e == nil || strings.TrimSpace(e.url) == "" {
		return
	}
	if strings.TrimSpace(rep.QueuedAt) == "" {
		rep.QueuedAt = time.Now().UTC().Format(time.RFC3339)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.post(ctx, rep); err != nil {
		e.queue(rep, err)
		return
	}
	if e.logf != nil {
		e.logf("enrolment_reported_to_control_plane identity=%q tenant=%q — the CP's inventory now names it, "+
			"so the next config bundle will not drop it from admission", rep.Identity, rep.TenantID)
	}
}

// post makes the one call. A 409/404 from the CP is NOT retried: those mean the identity is unassigned or
// owned by another tenant, which is an operator decision this Edge cannot resolve by trying again.
func (e *enrolmentCPReporter) post(ctx context.Context, rep enrolmentReport) error {
	body, err := json.Marshal(struct {
		Identity   string `json:"identity"`
		Group      string `json:"group,omitempty"`
		Note       string `json:"note,omitempty"`
		MachineRef string `json:"machine_ref,omitempty"`
	}{Identity: rep.Identity, Group: rep.Group, Note: rep.Note, MachineRef: rep.MachineRef})
	if err != nil {
		return err
	}
	// ★ AND IT FOLLOWS LEADERSHIP, like the pull and the fleet report (2026-08-25). The durable outbox means
	// a control plane that is briefly away costs a retry rather than an enrolment — but a leadership move is
	// not briefly away, and against a fixed address the outbox simply grows for as long as the authority is
	// in another region. What was enrolled here would reach the deployment only if leadership came back.
	base := strings.TrimRight(e.url, "/")
	if current := controlChannelCurrentBaseURL(); current != "" {
		base = strings.TrimRight(current, "/")
	}
	url, client := base+"/admin/enrolled-devices", e.client
	machine := strings.TrimSpace(e.machineURL) != "" && e.machineClient != nil
	if machine {
		// The organization travels in the BODY here rather than in a header, because this door is not an
		// operator acting on somebody: it is a node saying where a device enrolled, and the receiver decides.
		body, err = json.Marshal(struct {
			Identity   string `json:"identity"`
			TenantID   string `json:"tenant_id"`
			Group      string `json:"group,omitempty"`
			Note       string `json:"note,omitempty"`
			MachineRef string `json:"machine_ref,omitempty"`
		}{Identity: rep.Identity, TenantID: rep.TenantID, Group: rep.Group, Note: rep.Note,
			MachineRef: rep.MachineRef})
		if err != nil {
			return err
		}
		// The write door of whichever region leads, falling back to the configured one. See
		// controlChannelCurrentDataURL: the outbox meant nothing was lost and nothing arrived either.
		machineBase := strings.TrimRight(e.machineURL, "/")
		if current := controlChannelCurrentDataURL(); current != "" {
			machineBase = strings.TrimRight(current, "/") + machineDoorPath(e.machineURL)
		}
		url, client = machineBase, e.machineClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	if !machine {
		req.Header.Set("Authorization", "Bearer "+e.token)
		// The Edge authenticates as an operator; X-Operate-Tenant names the tenant the device actually enrolled
		// into. Without it the CP would file the device as unassigned, which is a different (and wrong) claim.
		if t := strings.TrimSpace(rep.TenantID); t != "" {
			req.Header.Set("X-Operate-Tenant", t)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusNotFound {
		return errNotRetryable{status: resp.StatusCode}
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("control plane refused the enrolment report: HTTP %d", resp.StatusCode)
	}
	return nil
}

// errNotRetryable marks a refusal that retrying cannot fix.
type errNotRetryable struct{ status int }

func (e errNotRetryable) Error() string {
	return fmt.Sprintf("control plane refused the enrolment report and retrying will not help: HTTP %d", e.status)
}

// queue writes the report to the durable outbox so a later drain can deliver it.
func (e *enrolmentCPReporter) queue(rep enrolmentReport, cause error) {
	if nr, ok := cause.(errNotRetryable); ok {
		// Loud, and NOT queued: the CP is answering, and its answer is that this identity is not this Edge's
		// to claim. Queuing would turn one refusal into a permanent retry loop against a settled decision.
		if e.logf != nil {
			e.logf("★ enrolment_report_refused identity=%q tenant=%q status=%d — this device holds a valid "+
				"certificate issued HERE but the control plane will not name it, so the next config bundle "+
				"WILL drop it from admission. An administrator has to resolve the ownership on the control "+
				"plane; the device cannot enrol again", rep.Identity, rep.TenantID, nr.status)
		}
		return
	}
	if strings.TrimSpace(e.outboxPath) == "" {
		if e.logf != nil {
			e.logf("★ enrolment_report_lost identity=%q tenant=%q error=%q — no outbox is configured, so this "+
				"enrolment is not recorded anywhere the control plane will see. The device will be dropped "+
				"from admission at the next config bundle", rep.Identity, rep.TenantID, cause.Error())
		}
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	line, err := json.Marshal(rep)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(e.outboxPath), 0o700); err != nil && e.logf != nil {
		e.logf("enrolment_report_outbox: cannot create %s: %v", filepath.Dir(e.outboxPath), err)
	}
	f, err := os.OpenFile(e.outboxPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		if e.logf != nil {
			e.logf("★ enrolment_report_lost identity=%q tenant=%q error=%q outbox_error=%q — the report could "+
				"not be delivered NOR queued; this device will be dropped from admission at the next bundle",
				rep.Identity, rep.TenantID, cause.Error(), err.Error())
		}
		return
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		if e.logf != nil {
			e.logf("★ enrolment_report_lost identity=%q write_error=%q", rep.Identity, err.Error())
		}
		return
	}
	// Sync, because the case this exists for is the Edge being restarted while the CP is down.
	_ = f.Sync()
	if e.logf != nil {
		e.logf("enrolment_report_queued identity=%q tenant=%q error=%q — queued for retry; until it is "+
			"delivered the control plane does not know this device exists", rep.Identity, rep.TenantID, cause.Error())
	}
}

// drain retries the outbox until it is empty. Runs for the life of the process.
func (e *enrolmentCPReporter) drain(ctx context.Context, every time.Duration) {
	if e == nil || strings.TrimSpace(e.outboxPath) == "" {
		return
	}
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.drainOnce(ctx)
		}
	}
}

// drainOnce delivers what it can and rewrites the outbox with what is left. Rewriting (rather than deleting
// per line) keeps the file consistent if the process dies mid-drain: either the old file or the new one.
func (e *enrolmentCPReporter) drainOnce(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()

	f, err := os.Open(e.outboxPath)
	if err != nil {
		return // no outbox = nothing pending
	}
	var pending []enrolmentReport
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rep enrolmentReport
		if err := json.Unmarshal([]byte(line), &rep); err != nil {
			continue // an unparseable line is dropped rather than retried for ever
		}
		pending = append(pending, rep)
	}
	f.Close()
	if len(pending) == 0 {
		_ = os.Remove(e.outboxPath)
		return
	}

	var stillPending []enrolmentReport
	delivered := 0
	for _, rep := range pending {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := e.post(cctx, rep)
		cancel()
		switch {
		case err == nil:
			delivered++
		case isNotRetryable(err):
			// Dropped from the outbox for the same reason it is not queued in the first place, and said once
			// more here because this is the last time anything will mention this device.
			if e.logf != nil {
				e.logf("★ enrolment_report_refused identity=%q tenant=%q error=%q — giving up; an "+
					"administrator must resolve this on the control plane", rep.Identity, rep.TenantID, err.Error())
			}
		default:
			stillPending = append(stillPending, rep)
		}
	}

	if len(stillPending) == 0 {
		_ = os.Remove(e.outboxPath)
	} else {
		var buf bytes.Buffer
		for _, rep := range stillPending {
			line, err := json.Marshal(rep)
			if err != nil {
				continue
			}
			buf.Write(append(line, '\n'))
		}
		tmp := e.outboxPath + ".tmp"
		if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err == nil {
			_ = os.Rename(tmp, e.outboxPath)
		}
	}
	if e.logf != nil && (delivered > 0 || len(stillPending) > 0) {
		e.logf("enrolment_report_outbox: delivered=%d still_pending=%d", delivered, len(stillPending))
	}
}

func isNotRetryable(err error) bool {
	_, ok := err.(errNotRetryable)
	return ok
}

// enrolmentOutboxPath answers "where does a report wait" with something that is never empty.
//
// durableStorePath returns "" when no -state-dir is configured, which is the ordinary case for an Edge
// launched from a script rather than from compose — and an empty path here does not degrade the feature, it
// deletes it: every report that cannot be delivered immediately is discarded, and the device it names is
// dropped at the next config bundle with nothing left to say why. The log directory is always configured
// (it has a default) and is on the same durable storage the audit records use, so it is the floor.
func enrolmentOutboxPath(stateDir, logDir string) string {
	if p := strings.TrimSpace(durableStorePath(stateDir, "", "enrolment_cp_outbox")); p != "" {
		return p
	}
	if d := strings.TrimSpace(logDir); d != "" {
		return filepath.Join(d, "enrolment_cp_outbox.jsonl")
	}
	return ""
}

// machineDoorPath keeps the PATH of the configured machine door when only its host should move. The door is
// configured as a full URL ending in a path, and substituting the host alone would otherwise post the body to
// the root — which answers 404 and reads as "the authority does not know this route".
func machineDoorPath(configured string) string {
	u, err := neturl.Parse(strings.TrimSpace(configured))
	if err != nil || u.Path == "" || u.Path == "/" {
		return ""
	}
	return strings.TrimRight(u.Path, "/")
}
