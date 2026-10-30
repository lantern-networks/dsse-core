package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/dns"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantca"
	"golang.org/x/net/dns/dnsmessage"
)

// Review #28: POST /steer/dns-query must NOT be an unauthenticated open resolver. Every sibling /steer/*
// control endpoint 401s a caller with no verified device transport identity; dns-query was registered raw
// with no gate. A request with no verified mTLS client cert (r.TLS == nil, as httptest produces) must be
// rejected with 401 before the resolver runs.
func TestSteerDNSQueryRequiresVerifiedDeviceIdentity(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "tenant_lab_001"}},
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})

	// A non-empty body so the request would otherwise reach the resolver; the gate must reject it first.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/steer/dns-query", strings.NewReader("not-a-real-dns-query"))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /steer/dns-query status = %d, want 401 (open-resolver guard)", rec.Code)
	}
}

func TestSteerDNSQueryRecordsOnlyCertificateTenantConntrack(t *testing.T) {
	const seed, other = "tenant_dns_seed", "tenant_dns_other"
	const resolvedIP = "10.234.0.8"
	t.Setenv("DSSE_DNS_STUB", "seed.internal="+resolvedIP+",other.internal="+resolvedIP)
	dir := t.TempDir()
	caSeed := makeTestCA(t, dir, "dns-seed-ca", 103)
	caOther := makeTestCA(t, dir, "dns-other-ca", 104)
	reg, err := tenantca.LoadTenantCARegistry(writeRegistry(t, dir, map[string]string{
		seed: caSeed.pemPath, other: caOther.pemPath,
	}))
	if err != nil {
		t.Fatal(err)
	}
	chains := map[string][][]*x509.Certificate{
		seed:  leafSignedBy(t, caSeed, "dns-seed-device", reg.Pool),
		other: leafSignedBy(t, caOther, "dns-other-device", reg.Pool),
	}
	for tenant, chain := range chains {
		if len(chain) == 0 {
			t.Fatalf("%s certificate did not verify", tenant)
		}
	}
	conntrack := dns.NewConntrackStore()
	handler := newServerWithConfig(serverConfig{
		Evaluator: decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: seed}},
		Registry:  connector.NewRegistry(), AdminAuth: newAdminAuthStore(),
		TenantCARegistry: reg, DNSConntrack: conntrack, LabMode: boolPtr(false),
	})
	for _, tc := range []struct{ tenant, qname string }{
		{seed, "seed.internal."}, {other, "other.internal."},
	} {
		query := dnsmessage.Message{Questions: []dnsmessage.Question{{
			Name: dnsmessage.MustNewName(tc.qname), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
		}}}
		raw, err := query.Pack()
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/steer/dns-query", bytes.NewReader(raw))
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[tc.tenant][0][0]}, VerifiedChains: chains[tc.tenant]}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s dns query: status=%d", tc.tenant, w.Code)
		}
	}
	for _, tc := range []struct{ tenant, want string }{
		{seed, "seed.internal"}, {other, "other.internal"},
	} {
		got, _, ok := conntrack.LookupFQDN(tc.tenant, resolvedIP, time.Now())
		if !ok || got != tc.want {
			t.Fatalf("tenant %q conntrack=%q found=%t, want %q", tc.tenant, got, ok, tc.want)
		}
	}
}
