package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/inspectioncrl"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func crlRouteFixture(t *testing.T) (*tenantInterceptionAuthority, *x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, []byte, time.Time, *bool) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	root, rootKey := interceptionTestCA(t, "Offline Tenant Root", nil, nil, now)
	issuing, key := interceptionTestCA(t, "Tenant Issuing", root, rootKey, now)
	template := *issuing
	points, err := inspectioncrl.URLs([]string{"http://192.0.2.1:80", "http://192.0.2.2:80", "http://192.0.2.3:80"}, "tenant_customer", root)
	if err != nil {
		t.Fatal(err)
	}
	template.CRLDistributionPoints = points
	der, err := x509.CreateCertificate(rand.Reader, &template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuing, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := inspectioncrl.Sign(root, rootKey, big.NewInt(1), nil, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fail := false
	a := newTenantInterceptionAuthority(nil, func([]byte) error {
		if fail {
			return errors.New("durable store unavailable")
		}
		return nil
	}, func() time.Time { return now })
	if _, err = a.Import("tenant_customer", certPEMForTest(root), certPEMForTest(issuing), ecKeyPEMForTest(t, key), crl); err != nil {
		t.Fatal(err)
	}
	return a, root, rootKey, issuing, crl, now, &fail
}

func TestInspectionCRLMachineRouteRequiresOperatorEdgeProof(t *testing.T) {
	a, root, _, _, crl, _, _ := crlRouteFixture(t)
	registry := tenantca.NewTenantCARegistry()
	customerCA, customerPEM := materialRouteTestCA(t, "Customer Device CA")
	if _, err := registry.Register("tenant_customer", customerPEM); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerTenantInspectionCRLRoute(mux, a, "bearer", registry)
	call := func(bearer, edge string, customer, verified bool, query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/tenant-inspection-crl?"+query, nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		if edge != "" {
			leaf := &x509.Certificate{Subject: pkix.Name{CommonName: edge}}
			chain := []*x509.Certificate{leaf}
			if customer {
				chain = append(chain, customerCA)
			}
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
			if verified {
				req.TLS.VerifiedChains = [][]*x509.Certificate{chain}
			}
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	query := "tenant=tenant_customer&issuer=" + inspectioncrl.Fingerprint(root)
	rec := call("bearer", "edge-a", false, true, query)
	if rec.Code != 200 {
		t.Fatalf("identified operator Edge refused: %d %s", rec.Code, rec.Body.String())
	}
	var got inspectionCRLStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if string(got.DER) != string(crl) || got.Tenant != "tenant_customer" {
		t.Fatal("wrong signed status")
	}
	for _, tc := range []struct {
		name, bearer, edge, query string
		customer, verified        bool
		code                      int
	}{
		{"bearer_only", "bearer", "", query, false, false, 403}, {"wrong_bearer", "wrong", "edge-a", query, false, true, 401},
		{"unverified", "bearer", "edge-a", query, false, false, 403}, {"customer_cert", "bearer", "customer-laptop", query, true, true, 403},
		{"missing_tenant", "bearer", "edge-a", "issuer=" + inspectioncrl.Fingerprint(root), false, true, 400},
		{"duplicate_tenant", "bearer", "edge-a", query + "&tenant=other", false, true, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := call(tc.bearer, tc.edge, tc.customer, tc.verified, tc.query).Code; got != tc.code {
				t.Fatalf("got %d want %d", got, tc.code)
			}
		})
	}
}

func TestInspectionCRLPublicationBindsIssuedEdgeTenantAndDurability(t *testing.T) {
	a, _, _, _, _, now, fail := crlRouteFixture(t)
	mat, err := a.IssueFor("tenant_customer", "edge-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert := parseAllCerts([]byte(mat.ChainPEM))[0]
	if len(cert.CRLDistributionPoints) != 3 {
		t.Fatalf("Edge issuer lost redundant CRL origins: %v", cert.CRLDistributionPoints)
	}
	key, err := parseECKeyPEM([]byte(mat.KeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	fp := inspectioncrl.Fingerprint(cert)
	mux := http.NewServeMux()
	registerTenantInspectionCRLRoute(mux, a, "bearer", nil)
	call := func(tenant, edge string, der []byte) int {
		body, _ := json.Marshal(map[string]any{"tenant_id": tenant, "issuer_sha256": fp, "der": der})
		req := httptest.NewRequest("POST", "/tenant-inspection-crl", strings.NewReader(string(body)))
		req.Header.Set("Authorization", "Bearer bearer")
		leaf := &x509.Certificate{Subject: pkix.Name{CommonName: edge}}
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	der, err := inspectioncrl.Sign(cert, key, big.NewInt(1), nil, now, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if code := call("tenant_customer", "edge-a", der); code != 204 {
		t.Fatalf("owned issued CRL refused: %d", code)
	}
	if call("tenant_customer", "edge-b", der) != 409 || call("other_tenant", "edge-a", der) != 409 {
		t.Fatal("unowned or cross-tenant issuer accepted")
	}
	bad := append([]byte(nil), der...)
	bad[len(bad)-1] ^= 1
	if call("tenant_customer", "edge-a", bad) != 409 {
		t.Fatal("tampered status accepted")
	}
	next, _ := inspectioncrl.Sign(cert, key, big.NewInt(2), nil, now, 5*time.Minute)
	*fail = true
	if call("tenant_customer", "edge-a", next) != 409 {
		t.Fatal("durability failure ACKed")
	}
	*fail = false
	status, err := a.crlStatus(context.Background(), "tenant_customer", fp)
	if err != nil || string(status.DER) != string(der) {
		t.Fatal("failed persistence replaced committed status:", err)
	}
	if err = a.revokeDelegation(context.Background(), "tenant_customer", fp); err != nil {
		t.Fatal(err)
	}
	_, err = a.crlStatus(context.Background(), "tenant_customer", fp)
	if err != nil {
		t.Fatal("recorded signed leaf status should stay available after CA revocation:", err)
	}
}

func TestInspectionCRLPublicCDPServesOnlyCommittedDERAtItsOwnHost(t *testing.T) {
	a, root, _, issuing, rootCRL, now, fail := crlRouteFixture(t)
	mux := http.NewServeMux()
	registerTenantInspectionCRLPublicRoute(mux, a)
	get := func(host, tenant string, issuer *x509.Certificate, query string) *httptest.ResponseRecorder {
		t.Helper()
		path := "/pki/crl/" + tenant + "/" + inspectioncrl.Fingerprint(issuer) + ".crl" + query
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = host
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	hosts := []string{"192.0.2.1:80", "192.0.2.2:80", "192.0.2.3:80"}
	host := hosts[0]
	rootResponse := get(host, "tenant_customer", root, "")
	if rootResponse.Code != 200 || rootResponse.Header().Get("Content-Type") != "application/pkix-crl" || string(rootResponse.Body.Bytes()) != string(rootCRL) {
		t.Fatal("the root CDP did not return its committed signed DER")
	}
	for _, alternate := range hosts[1:] {
		if got := get(alternate, "tenant_customer", root, ""); got.Code != 200 || string(got.Body.Bytes()) != string(rootCRL) {
			t.Fatalf("alternate root CDP %s unavailable", alternate)
		}
	}
	first := get(host, "tenant_customer", issuing, "")
	second := get(host, "tenant_customer", issuing, "")
	if first.Code != 200 || string(first.Body.Bytes()) != string(second.Body.Bytes()) {
		t.Fatal("a read must serve one stable committed CRL without signing again")
	}
	for _, alternate := range hosts[1:] {
		if got := get(alternate, "tenant_customer", issuing, ""); got.Code != 200 || string(got.Body.Bytes()) != string(first.Body.Bytes()) {
			t.Fatalf("alternate issuing CDP %s differs from committed CRL", alternate)
		}
	}
	if _, err := inspectioncrl.ParseAndValidate(first.Body.Bytes(), issuing, now); err != nil {
		t.Fatal("served issuing CRL is not valid:", err)
	}
	for _, bad := range []*httptest.ResponseRecorder{
		get("other.example", "tenant_customer", root, ""),
		get(host, "other_tenant", root, ""),
		get(host, "tenant_customer", root, "?token=unexpected"),
	} {
		if bad.Code == 200 || string(bad.Body.Bytes()) == string(rootCRL) {
			t.Fatal("wrong host, tenant, or query exposed the CRL")
		}
	}
	// A failed durable write cannot change the bytes a client receives.
	a.now = func() time.Time { return now.Add(4 * time.Minute) }
	*fail = true
	if err := a.refreshIssuingCRLs(context.Background()); err == nil {
		t.Fatal("CRL refresh falsely acknowledged a failed durable write")
	}
	*fail = false
	if got := get(host, "tenant_customer", issuing, ""); got.Code != 200 || string(got.Body.Bytes()) != string(first.Body.Bytes()) {
		t.Fatal("failed refresh replaced the last committed CRL")
	}
	if err := a.refreshIssuingCRLs(context.Background()); err != nil {
		t.Fatal("CRL refresh failed:", err)
	}
	newer := get(host, "tenant_customer", issuing, "")
	if newer.Code != 200 || string(newer.Body.Bytes()) == string(first.Body.Bytes()) {
		t.Fatal("scheduled refresh did not publish new signed bytes")
	}
	priorList, _ := x509.ParseRevocationList(first.Body.Bytes())
	nextList, _ := x509.ParseRevocationList(newer.Body.Bytes())
	if nextList.Number.Cmp(priorList.Number) <= 0 {
		t.Fatal("CRL number did not increase")
	}
}

func TestCRLHostAcceptsElidedDefaultHTTPPortOnly(t *testing.T) {
	base, _ := url.Parse("http://crl.example.test:80")
	if !sameCRLHTTPHost("crl.example.test", base) || !sameCRLHTTPHost("crl.example.test:80", base) {
		t.Fatal("HTTP client eliding port 80 cannot fetch CDP")
	}
	if sameCRLHTTPHost("crl.example.test:8080", base) || sameCRLHTTPHost("other.example.test:80", base) {
		t.Fatal("CRL host accepted a different origin")
	}
}

func TestInspectionCRLAdminRoutesRemainRegisteredWithoutAuthority(t *testing.T) {
	mux := http.NewServeMux()
	registerTenantInspectionCRLAdminRoutes(mux, func(_ string, next http.HandlerFunc) http.HandlerFunc {
		return next
	}, nil, nil)
	for _, path := range []string{
		"/admin/tenant-interception-authority/root-crl",
		"/admin/tenant-interception-authority/revoke-delegation",
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status = %d, want 503", path, rec.Code)
		}
	}
}

func TestInspectionRootCRLRemainsPublicAfterIssuingAuthorityRevocation(t *testing.T) {
	a, root, rootKey, issuing, _, now, _ := crlRouteFixture(t)
	revoked, err := inspectioncrl.Sign(root, rootKey, big.NewInt(2), []x509.RevocationListEntry{{SerialNumber: issuing.SerialNumber, RevocationTime: now}}, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.updateRootCRL(context.Background(), "tenant_customer", revoked); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerTenantInspectionCRLPublicRoute(mux, a)
	req := httptest.NewRequest(http.MethodGet, "/pki/crl/tenant_customer/"+inspectioncrl.Fingerprint(root)+".crl", nil)
	req.Host = "192.0.2.1:80"
	out := httptest.NewRecorder()
	mux.ServeHTTP(out, req)
	if out.Code != http.StatusOK || string(out.Body.Bytes()) != string(revoked) {
		t.Fatalf("committed root revocation became unavailable: %d %s", out.Code, out.Body.String())
	}
	if _, err = a.IssueFor("tenant_customer", "edge-a", time.Hour); err == nil {
		t.Fatal("revoked issuing authority still issued new material")
	}
}
