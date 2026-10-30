package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/lantern-networks/dsse-core/tenantca"
)

type authFlowResultStore interface {
	Record(authFlowResult) error
	Lookup(requestID, tenantID, deviceID, principal, session string) (string, error)
}

// An enforcing Edge has no direct database access. The existing Edge machine
// mTLS identity reaches the CP authority; there is no browser/cookie path to
// this API. A failed or ambiguous write remains unknown to the agent.
type remoteAuthResultStore struct {
	url    string
	client *http.Client
}

func authResultEdgeAuthorized(r *http.Request, reg *tenantca.TenantCARegistry, tenant string) bool {
	shipper, verified := auditIngestShipperFrom(r, reg)
	// A tenant-issued endpoint certificate is not an Edge certificate. The
	// single-tenant CA fallback for legacy reports cannot authorize results.
	return verified && auditIngestAuthorityMap != nil && edgeMayShipForTenant(shipper, tenant)
}

// Results use the management listener just like the grant authority, including
// when the current leader belongs to a different Region.
func (s remoteAuthResultStore) managementURL() string {
	if base := controlChannelCurrentBaseURL(); base != "" {
		return strings.TrimRight(base, "/") + "/auth-flow-results"
	}
	return s.url
}

func (s remoteAuthResultStore) Record(r authFlowResult) error {
	if s.client == nil || s.url == "" {
		return errors.New("authentication result authority unavailable")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, s.managementURL(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("authentication result authority status %d", resp.StatusCode)
	}
	return nil
}

func (s remoteAuthResultStore) Lookup(id, tenant, device, principal, session string) (string, error) {
	if s.client == nil || s.url == "" {
		return "", errors.New("authentication result authority unavailable")
	}
	body, err := json.Marshal(struct {
		RequestID string `json:"request_id"`
		TenantID  string `json:"tenant_id"`
		DeviceID  string `json:"device_id"`
		Principal string `json:"os_principal"`
		Session   string `json:"os_session"`
	}{id, tenant, device, principal, session})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, s.managementURL()+"/query", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication result authority status %d", resp.StatusCode)
	}
	var result struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256)).Decode(&result); err != nil {
		return "", err
	}
	if result.Result != "resumed" && result.Result != "not_resumed" {
		return "", errors.New("invalid authentication result authority response")
	}
	return result.Result, nil
}

// Only a verified Edge machine certificate admitted for this tenant may write
// or read the CP result ledger. Not registered on a config-pulling Edge.
func registerAuthResultAuthorityRoutes(mux *http.ServeMux, store authFlowResultStore, configSourceURL string, authorizeEdge func(*http.Request, string) bool) {
	if store == nil || strings.TrimSpace(configSourceURL) != "" {
		return
	}
	mux.HandleFunc("POST /auth-flow-results", func(w http.ResponseWriter, r *http.Request) {
		var value authFlowResult
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		if dec.Decode(&value) != nil || dec.Decode(&struct{}{}) != io.EOF ||
			!authorizeEdge(r, value.TenantID) {
			http.Error(w, "result unavailable", http.StatusForbidden)
			return
		}
		if err := store.Record(value); err != nil {
			http.Error(w, "result not confirmed", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /auth-flow-results/query", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			RequestID string `json:"request_id"`
			TenantID  string `json:"tenant_id"`
			DeviceID  string `json:"device_id"`
			Principal string `json:"os_principal"`
			Session   string `json:"os_session"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512))
		if dec.Decode(&q) != nil || dec.Decode(&struct{}{}) != io.EOF {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		tenant := q.TenantID
		if !authorizeEdge(r, tenant) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		result, err := store.Lookup(q.RequestID, tenant, q.DeviceID, q.Principal, q.Session)
		if err != nil {
			http.Error(w, "result unavailable", http.StatusServiceUnavailable)
			return
		}
		if result == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"result": result})
	})
}
