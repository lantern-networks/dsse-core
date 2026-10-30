package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPartialMaterialAnswerDoesNotRetireUnresolvedOrganizations(t *testing.T) {
	for _, refusal := range []string{"Acme: temporarily unable to sign", "Acme: " + authorityNotAskedPhrase} {
		t.Run(refusal, func(t *testing.T) {
			useEmptyTenantCertificateIndex(t)
			authority := newTenantTransportAuthority(nil, nil, time.Now)
			var good tenantTransportMaterial
			for _, tenant := range []string{"Acme", "tenant_ok"} {
				if _, err := authority.EnsureCA(tenant, tenant+".example.test"); err != nil {
					t.Fatal(err)
				}
				material, err := authority.IssueFor(tenant, "edge-a", time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if err := installTenantTransportMaterial(material); err != nil {
					t.Fatal(err)
				}
				if tenant == "tenant_ok" {
					good = material
				}
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"materials": []tenantTransportMaterial{good}, "generation": 1, "refused": []string{refusal}})
			}))
			defer srv.Close()
			f := &tenantTransportMaterialFetcher{endpoint: srv.URL, client: srv.Client(), tenants: func() []string { return nil }, log: func(string, ...any) {}}
			_, _ = f.FetchOnce()
			if f.OrganizationIsGone("Acme") || transportTenantCertificates.IsRetiring("Acme") {
				t.Fatal("partial answer was treated as proof Acme was deleted")
			}
		})
	}
}
