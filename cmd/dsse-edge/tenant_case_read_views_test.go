package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

func TestDeviceRetirementPreviewUsesExactTenant(t *testing.T) {
	a := newTenantDeviceAuthority(nil, nil, time.Now)
	for _, tenant := range []string{"Acme", "acme"} {
		if _, err := a.EnsureCA(tenant, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := a.RotateCA(tenant); err != nil {
			t.Fatal(err)
		}
	}
	before := encodeAuthoritySnapshot(a.cas)
	want := a.cas["Acme"].Incoming.CACertPEM
	called := false
	out := previewDeviceRetirement(a, " Acme ", []pkiTransitionAdmission{func(c pkiAuthorityTransition) error {
		called = true
		if c.Tenant != "Acme" || c.DeviceAfter.CACertPEM != want {
			t.Error("retirement readiness examined a different tenant")
		}
		return nil
	}})
	if !called || !out.Allowed {
		t.Fatalf("own tenant preview failed: %+v", out)
	}
	if !bytes.Equal(before, encodeAuthoritySnapshot(a.cas)) {
		t.Fatal("read-only preview modified signing authority")
	}
}

func TestConnectorIdentityViewUsesExactTenant(t *testing.T) {
	r := connector.NewRegistry()
	for id, tenant := range map[string]string{"upper-connector": "Acme", "lower-connector": "acme"} {
		_, err := r.Register(model.ConnectorRegistration{ID: id, TenantID: tenant, PrivateBaseURL: "http://connector.internal", Status: "healthy"}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	for tenant, own := range map[string]string{"Acme": "upper-connector", "acme": "lower-connector"} {
		got := connectorIdentitiesFor(r, tenant)
		if len(got) != 1 || !got[own] {
			t.Errorf("tenant %q connector view contains another tenant's identity: %v", tenant, got)
		}
	}
	if len(connectorIdentitiesFor(r, "")) != 2 {
		t.Fatal("deployment-wide view lost a connector")
	}
}
