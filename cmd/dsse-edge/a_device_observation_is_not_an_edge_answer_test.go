package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/dns"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// A DNS observation reported from outside — here by an ordinary enrolled device, with no connector registry
// entry and no runtime secret — is recorded for address-to-name recovery and is never this Edge's answer for
// the name: it must not decide where a named flow goes.
func TestADeviceObservationDoesNotBecomeAnEdgeAnswer(t *testing.T) {
	const tenant = "review-tenant-a"
	const dev = "device-review-a"
	dir := t.TempDir()
	ca := makeTestCA(t, dir, "review-local-ca", 7001)
	caReg, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{tenant: ca.pemPath}))
	if err != nil {
		t.Fatal(err)
	}
	chains := leafSignedBy(t, ca, dev, caReg.Pool)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ct := dns.NewConntrackStore()
	reg := connector.NewRegistry()
	_, err = reg.Register(model.ConnectorRegistration{ID: "connector-review-site", TenantID: tenant, ConnectorGroupID: "site-a", Status: "active", PrivateBaseURL: "https://internal.invalid", ReachableRoutes: model.ConnectorReachableRoutes{CIDRs: []string{"10.55.1.0/24"}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	evaluator := testEvaluatorWithPolicies(nil)
	evaluator.PolicyBundle.TenantID = tenant
	h := dataPlaneOnlyMiddleware(newServerWithConfig(serverConfig{Evaluator: evaluator, Writer: writer, Registry: reg, TenantCARegistry: caReg, DNSConntrack: ct, LabMode: boolPtr(false)}))
	post := func(body string) int {
		r := httptest.NewRequest(http.MethodPost, "/ingest/dns-resolution-observation", strings.NewReader(body))
		r.Header.Set(connectorIDHeader, dev)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[0][0]}, VerifiedChains: chains}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	// Sanity/control: the same proof cannot claim another tenant.
	foreignStatus := post(`{"tenant_id":"review-tenant-b","fqdn":"files.review.invalid","resolved_ips":["10.55.1.99"],"ttl_seconds":300}`)
	if foreignStatus != http.StatusForbidden {
		t.Fatalf("foreign tenant status=%d, want 403", foreignStatus)
	}
	status := post(`{"fqdn":"files.review.invalid","resolved_ips":["10.55.1.99"],"ttl_seconds":300}`)
	prev := observeResolver
	lookups := 0
	observeResolver = func(context.Context, string) ([]net.IP, error) {
		lookups++
		return nil, fmt.Errorf("test resolver has never answered this name")
	}
	observeLocality = newObserveLocalityCache()
	t.Cleanup(func() { observeResolver = prev; observeLocality = newObserveLocalityCache() })
	addr, ok := registeredAddressBehindName(context.Background(), reg, ct.LookupAddresses, tenant, "files.review.invalid", time.Now())
	t.Logf("production gate: own-tenant HTTP=%d, foreign-tenant HTTP=%d; ordinary device known as connector=false; converted address=%q accepted=%t; Edge resolver calls=%d", status, foreignStatus, addr, ok, lookups)
	if status == http.StatusOK && ok && addr == "10.55.1.99" && lookups == 0 {
		t.Fatal("device-supplied DNS observation was promoted to the trusted Edge answer used to rewrite the destination")
	}
}
