package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestConnectorDirectoryImportsUseVerifiedTenant(t *testing.T) {
	const seed, caller = "tenant_lab_001", "tenant_customer"
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "directory-customer", 710)
	cas, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{caller: ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chain := leafSignedBy(t, ca, "directory-connector", cas.Pool)
	if len(chain) == 0 {
		t.Fatal("fixture certificate did not verify")
	}
	store := humanidentity.NewHumanIdentityDirectoryStore()
	for _, tenant := range []string{seed, caller} {
		_, err := humanidentity.HumanIdentityDirectoryUpsertSourcePolicy(context.Background(), store, tenant,
			humanidentity.HumanIdentitySourcePolicy{Source: "directory", ConnectorType: "scim", Enabled: true}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	reported := make(chan string, 1)
	var cpUnavailable atomic.Bool
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cpUnavailable.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var report directoryImportReport
		if r.URL.Path != "/directory-import-report" || json.NewDecoder(r.Body).Decode(&report) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reported <- report.TenantID
		w.WriteHeader(http.StatusOK)
	}))
	defer cp.Close()
	reporter := &directoryCPReporter{url: cp.URL, client: cp.Client()}
	mux := http.NewServeMux()
	registerHumanIdentityRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		testEvaluator(), nil, store, nil, connector.NewRegistry(), "", false, true, "", reporter, cas)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set(connectorIDHeader, "directory-connector")
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chain[0][0]}, VerifiedChains: chain}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	t.Run("source list", func(t *testing.T) {
		w := call(http.MethodGet, "/identity-sources/due", "")
		var result humanidentity.HumanIdentitySourceDueListResponse
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusOK || result.TenantID != caller {
			t.Fatalf("source list status=%d tenant=%q", w.Code, result.TenantID)
		}
	})
	t.Run("import and CP report", func(t *testing.T) {
		w := call(http.MethodPost, "/identity-sources/import", `{"source":"directory","identities":[{"id":"person","subject":"person-sub","status":"active"}]}`)
		var result humanidentity.HumanIdentityDirectoryImportResponse
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusOK || result.TenantID != caller {
			t.Errorf("import status=%d tenant=%q", w.Code, result.TenantID)
		}
		select {
		case tenant := <-reported:
			if tenant != caller {
				t.Errorf("CP report targets %q", tenant)
			}
		case <-time.After(time.Second):
			t.Error("CP report missing")
		}
		rows, err := humanidentity.HumanIdentityDirectoryList(context.Background(), store, seed, time.Now(), humanidentity.HumanIdentityDirectoryListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if rows.Count != 0 {
			t.Errorf("import modified seed tenant: %d identities", rows.Count)
		}
	})
	t.Run("missing durable report rejects connector checkpoint", func(t *testing.T) {
		cpUnavailable.Store(true)
		defer cpUnavailable.Store(false)
		w := call(http.MethodPost, "/identity-sources/import", `{"source":"directory","identities":[{"id":"person-unconfirmed","subject":"unconfirmed","status":"active"}]}`)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("import without CP commit or durable outbox returned %d, want 503", w.Code)
		}
	})
	t.Run("foreign tenant payload", func(t *testing.T) {
		w := call(http.MethodPost, "/identity-sources/import", `{"source":"directory","identities":[{"id":"foreign","tenant_id":"tenant_lab_001","subject":"foreign","status":"active"}]}`)
		if w.Code < 400 {
			t.Fatalf("foreign identity accepted: %d", w.Code)
		}
	})
}
