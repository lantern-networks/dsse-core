package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/tenantca"
)

type tenantCAUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

var tenantCAAuthorMu sync.Mutex

// Pure control planes publish attribution; they do not terminate device TLS.
// Combined enforcement nodes keep the separate trust/attribution partial-write
// contract until their local trust store can participate in the same ordering.
func sharedTenantCAAuthor() (tenantCAUpdater, bool) {
	p, ok := tenantCARegistryShared.(tenantCAUpdater)
	return p, ok && edgeIsControlPlane && deviceClientCAs == nil
}

func sharedTenantCARead(reg *tenantca.TenantCARegistry) error {
	tenantCAAuthorMu.Lock()
	defer tenantCAAuthorMu.Unlock()
	raw, err := tenantCARegistryShared.Load()
	if err != nil {
		return err
	}
	if raw == nil {
		if reg.AuthoritativeLoaded() || reg.ConfigGeneration() != 0 || len(reg.Registrations()) != 0 {
			return fmt.Errorf("known tenant CA snapshot disappeared")
		}
		return nil
	}
	return reg.ReplaceAuthoritative(raw)
}

func sharedTenantCAWrite(w http.ResponseWriter, r *http.Request, reg *tenantca.TenantCARegistry, config serverConfig, writer *logs.Writer, outbox adminAuditOutboxDeadReader, evaluator decision.Evaluator, tenant, action, pem, fingerprint string) bool {
	p, ok := sharedTenantCAAuthor()
	if !ok {
		return false
	}
	tenantCAAuthorMu.Lock()
	defer tenantCAAuthorMu.Unlock()
	status := http.StatusServiceUnavailable
	added, removed, remaining := 0, 0, 0
	var committed []byte
	err := p.UpdateContext(r.Context(), func(raw []byte) ([]byte, error) {
		if raw == nil {
			if reg.AuthoritativeLoaded() || reg.ConfigGeneration() != 0 || len(reg.Registrations()) != 0 {
				return nil, fmt.Errorf("known tenant CA snapshot disappeared")
			}
			raw = []byte(`{"tenants":[]}`)
		}
		candidate, err := tenantca.RegistryFromSnapshot(raw)
		if err != nil {
			return nil, err
		}
		switch action {
		case "tenant_ca_register":
			certs, e := candidate.Register(tenant, []byte(pem))
			if e != nil {
				status = http.StatusConflict
				return nil, e
			}
			added = len(certs)
		case "tenant_ca_anchor_withdraw":
			exists := false
			for _, f := range candidate.Facts(time.Now()) {
				if strings.EqualFold(f.TenantID, tenant) {
					if f.SHA256 == fingerprint {
						exists = true
					} else {
						remaining++
					}
				}
			}
			if !exists {
				status = http.StatusNotFound
				return nil, fmt.Errorf("CA is not registered to this organization")
			}
			current := config
			current.TenantCARegistry = candidate
			if verdict := deviceCAWithdrawalGate(current, tenant, fingerprint, remaining); !verdict.Allowed {
				status = http.StatusConflict
				return nil, fmt.Errorf("withdrawal refused: %s", verdict.Text)
			}
			candidate.WithdrawAnchor(tenant, fingerprint)
			removed = 1
		case "tenant_ca_withdraw":
			removed = candidate.Withdraw(tenant)
		default:
			return nil, fmt.Errorf("unsupported CA mutation")
		}
		next, e := candidate.Snapshot()
		if e != nil {
			return nil, e
		}
		// Keep extension fields from the latest row, never from the local cache.
		var fields, known map[string]json.RawMessage
		if e = json.Unmarshal(raw, &fields); e != nil {
			return nil, e
		}
		json.Unmarshal(next, &known)
		delete(fields, "material_managed_tenants")
		for k, v := range known {
			fields[k] = v
		}
		committed, e = json.Marshal(fields)
		return committed, e
	})
	if err != nil {
		now := time.Now()
		a := adminTenantModelLifecycleAuditLogFor(r, adminTenantModel{TenantID: tenant}, action, evaluator, now)
		if action == "tenant_ca_register" {
			fingerprints := []string{}
			for _, cert := range parseAllCerts([]byte(pem)) {
				fingerprints = append(fingerprints, tenantca.CAAnchorKey(cert))
			}
			a.Metadata["ca_sha256"] = fingerprints
		}
		result := "error"
		a.Result = &result
		a.Metadata["applied"] = false
		a.Metadata["durable"] = false
		_ = appendAdminAudit(r.Context(), writer, outbox, a, now)
		message := "CA change was not committed; refresh and retry after storage or leadership recovers"
		if status < 500 {
			message = err.Error()
		}
		writeJSON(w, status, map[string]any{"error": message, "applied": false, "durable": false})
		return true
	}
	if err = reg.ReplaceAuthoritative(committed); err != nil {
		now := time.Now()
		a := adminTenantModelLifecycleAuditLogFor(r, adminTenantModel{TenantID: tenant}, action, evaluator, now)
		if action == "tenant_ca_register" {
			fingerprints := []string{}
			for _, cert := range parseAllCerts([]byte(pem)) {
				fingerprints = append(fingerprints, tenantca.CAAnchorKey(cert))
			}
			a.Metadata["ca_sha256"] = fingerprints
		}
		result := "error"
		a.Result = &result
		a.Metadata["durable"] = true
		a.Metadata["local_cache_applied"] = false
		_ = appendAdminAudit(r.Context(), writer, outbox, a, now)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "partial", "durable": true, "local_cache_applied": false, "error": "CA change committed but the local view could not refresh"})
		return true
	}
	now := time.Now()
	a := adminTenantModelLifecycleAuditLogFor(r, adminTenantModel{TenantID: tenant}, action, evaluator, now)
	if action == "tenant_ca_register" {
		fingerprints := []string{}
		for _, cert := range parseAllCerts([]byte(pem)) {
			fingerprints = append(fingerprints, tenantca.CAAnchorKey(cert))
		}
		a.Metadata["ca_sha256"] = fingerprints
	}
	a.Metadata["durable"] = true
	a.Metadata["applied"] = true
	_ = appendAdminAudit(r.Context(), writer, outbox, a, now)
	reply := map[string]any{"tenant_id": tenant, "durable": true, "applies_to": "the committed control-plane configuration; Edge adoption is not confirmed by this response"}
	code := http.StatusOK
	switch action {
	case "tenant_ca_register":
		code = http.StatusCreated
		reply["ca_added"] = added
		reply["trusted"] = true
	case "tenant_ca_anchor_withdraw":
		reply["withdrawn"] = fingerprint
		reply["cas_remaining"] = remaining
		reply["still_trusted"] = false
	case "tenant_ca_withdraw":
		reply["ca_removed"] = removed
		reply["still_trusted"] = "device trust removal requires its separate operation"
	}
	writeJSON(w, code, reply)
	return true
}
