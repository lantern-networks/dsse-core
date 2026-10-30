package main

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestSharedFleetDoesNotWidenTenantRegionPlacement(t *testing.T) {
	for _, tc := range []struct {
		allowed []string
		region  string
		pass    bool
	}{
		{nil, "region-a", true}, {[]string{"region-a", "region-c"}, "region-a", true},
		{[]string{"region-a"}, "region-b", false}, {[]string{"REGION-A"}, "region-a", true},
		{[]string{"region-a"}, "", false},
	} {
		check := newSharedFleetResidencyCheck("three-regions-multi-edge", tc.region, stubTenantResidencyStore{allowed: tc.allowed})
		if err := check(context.Background(), "tenant_lab_001"); (err == nil) != tc.pass {
			t.Fatalf("%v %s: %v", tc.allowed, tc.region, err)
		}
	}
	check := newSharedFleetResidencyCheck("three-regions-multi-edge", "region-a", nil)
	if check(context.Background(), "tenant_lab_001") == nil {
		t.Fatal("unknown tenant placement failed open")
	}
	if newSharedFleetResidencyCheck("one-region-three-nodes", "region-a", nil) != nil {
		t.Fatal("legacy topology unexpectedly changed")
	}
	// The same rule runs before any authenticated native or Connector HTTP upgrade.
	registry := &tenantca.TenantCARegistry{Pool: x509.NewCertPool()}
	ca, pem := tenantCATestCA(t, "Region Restricted Tenant")
	if _, err := registry.Register("tenant_lab_001", pem); err != nil {
		t.Fatal(err)
	}
	denied := newSharedFleetResidencyCheck("three-regions-multi-edge", "region-b", stubTenantResidencyStore{allowed: []string{"region-a"}})
	handler := sharedFleetResidencyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("out-of-Region request reached data handler") }), serverConfig{TenantCARegistry: registry}, denied)
	for _, path := range []string{"/steer/mux", "/connectors/tunnel", "/swg/http-egress"} {
		r := httptest.NewRequest("POST", path, nil)
		r.TLS = tlsStateChainingTo(ca)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 503 {
			t.Fatalf("%s bypassed Region restriction: %d", path, w.Code)
		}
	}
}

func TestSharedFleetAuthenticationRefusesDisallowedRegionBeforeIdP(t *testing.T) {
	b, gate := ceremonyFixture(t)
	b.checkTenantRegion = newSharedFleetResidencyCheck("three-regions-multi-edge", "region-b", stubTenantResidencyStore{allowed: []string{"region-a"}})
	link := authTestSignedLink(gate, gate.stepUpURLFor("app:22", "corp", "", "device", "tenant_lab_001"))
	w := httptest.NewRecorder()
	b.handleStart(w, httptest.NewRequest("GET", link, nil))
	if w.Code != 503 || w.Header().Get("Location") != "" {
		t.Fatalf("disallowed Region started authentication: %d", w.Code)
	}
	if len(b.pending) != 0 || len(b.confirmations) != 0 {
		t.Fatal("out-of-boundary ceremony state created")
	}
}
