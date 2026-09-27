package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantca"
)

type delegatedRevocationReport struct {
	TenantID string `json:"tenant_id"`
	GrantID  string `json:"grant_id"`
	Reason   string `json:"reason"`
}

// Reconcile durable local revocations until the authority confirms them. Reports
// can only revoke existing grants, never create or expand a permission.
// restart-durability: ephemeral — confirmed is only a duplicate-report cache.
// Revocations live in the delegated-grant store; restart resends its revoked
// records, so a node-local store file is required for durable pending reports.
// populated-by: side_effect — report records a matching CP acknowledgment.
// An absent cache entry triggers another idempotent report, not a lost revocation.
type delegatedRevocationReporter struct {
	url       string
	client    *http.Client
	logf      func(string, ...interface{})
	mu        sync.Mutex
	confirmed map[string]struct{}
}

func (p *delegatedRevocationReporter) report(ctx context.Context, grant model.DelegatedAccessGrant) error {
	if p == nil || p.client == nil || strings.TrimSpace(p.url) == "" {
		return errors.New("control-plane revocation reporting is not configured")
	}
	if grant.Status != "revoked" {
		return errors.New("grant is not revoked")
	}
	body, _ := json.Marshal(delegatedRevocationReport{grant.TenantID, grant.ID, stringPtrValue(grant.RevocationReason)})
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.New("control-plane revocation could not be confirmed")
	}
	defer resp.Body.Close()
	var ack struct {
		TenantID string `json:"tenant_id"`
		GrantID  string `json:"grant_id"`
		Status   string `json:"status"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&ack) != nil || ack.TenantID != grant.TenantID || ack.GrantID != grant.ID || ack.Status != "revoked" {
		return errors.New("control-plane revocation could not be confirmed")
	}
	p.mu.Lock()
	if p.confirmed == nil {
		p.confirmed = make(map[string]struct{})
	}
	p.confirmed[delegatedRevocationKey(grant)] = struct{}{}
	p.mu.Unlock()
	return nil
}

func delegatedRevocationKey(grant model.DelegatedAccessGrant) string {
	b, _ := json.Marshal([]string{grant.TenantID, grant.ID, stringPtrValue(grant.RevokedAt), stringPtrValue(grant.RevocationReason)})
	return string(b)
}

func (p *delegatedRevocationReporter) reconcileOnce(ctx context.Context, store *delegatedgrant.Store) {
	if p == nil || store == nil {
		return
	}
	for _, grant := range store.Snapshot() {
		if grant.Status != "revoked" {
			continue
		}
		p.mu.Lock()
		_, confirmed := p.confirmed[delegatedRevocationKey(grant)]
		p.mu.Unlock()
		if confirmed {
			continue
		}
		if err := p.report(ctx, grant); err != nil && p.logf != nil {
			p.logf("delegated_revocation_report_unconfirmed tenant=%q grant=%q", grant.TenantID, grant.ID)
		}
	}
}
func (p *delegatedRevocationReporter) reconcile(ctx context.Context, store *delegatedgrant.Store, interval time.Duration) {
	if p == nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		p.reconcileOnce(ctx, store)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func registerDelegatedRevocationReport(mux *http.ServeMux, store *delegatedgrant.Store, registry *tenantca.TenantCARegistry, source string, devMode bool, writer *logs.Writer) {
	if store == nil || strings.TrimSpace(source) != "" {
		return
	}
	mux.HandleFunc("POST /delegated-grant-revocations", func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(captureCPWriteLease(r.Context()))
		shipper, verified := auditIngestShipperFrom(r, registry)
		if !verified && !devMode {
			writeError(w, http.StatusForbidden, errors.New("an authenticated Edge certificate is required"))
			return
		}
		var body delegatedRevocationReport
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		if dec.Decode(&body) != nil || dec.Decode(&struct{}{}) != io.EOF || strings.TrimSpace(body.TenantID) == "" || strings.TrimSpace(body.GrantID) == "" {
			writeError(w, http.StatusBadRequest, errors.New("invalid revocation report"))
			return
		}
		if (verified || !devMode) && !edgeMayShipForTenant(shipper, body.TenantID) {
			writeError(w, http.StatusForbidden, errors.New("Edge is not authorized to report for this tenant"))
			return
		}
		now := time.Now().UTC()
		_, err := store.RevokeForTenantContext(r.Context(), body.TenantID, body.GrantID, body.Reason, now)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, delegatedgrant.ErrAbsent) {
				status = http.StatusNotFound
			}
			if errors.Is(err, delegatedgrant.ErrPersistence) {
				status = http.StatusServiceUnavailable
			}
			writeError(w, status, errors.New("revocation could not be confirmed by the authority"))
			return
		}
		if writer != nil {
			if err := writer.Append("audit.log.jsonl", map[string]any{"event_type": "delegated_access_grant_revocation_reported", "tenant_id": body.TenantID, "grant_id": body.GrantID, "reporter": shipper.Identity, "result": "revoked", "timestamp": now.Format(time.RFC3339)}); err != nil {
				writeError(w, http.StatusServiceUnavailable, errors.New("revocation audit could not be confirmed"))
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"tenant_id": body.TenantID, "grant_id": body.GrantID, "status": "revoked"})
	})
}
