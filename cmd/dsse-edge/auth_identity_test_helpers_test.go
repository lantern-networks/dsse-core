package main

import (
	"net/url"
	"testing"

	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

const testAuthPrincipal = "windows:S-1-5-21-100-200-300-1001"
const testAuthSession = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func authTestAssign(t *testing.T, reg *idpregistry.Store, tenant, device, subject, provider string) idpregistry.Connection {
	t.Helper()
	c, ok := reg.Get(tenant, provider)
	if !ok {
		c = idpregistry.Connection{TenantID: tenant, IdPID: provider, Issuer: "https://idp.example", AuthorizationEndpoint: "https://idp.example/auth", ClientID: "client"}
	}
	found := false
	for i, b := range c.DeviceUserBindings {
		if b.DeviceID == device && b.OSPrincipal == testAuthPrincipal {
			c.DeviceUserBindings[i].Subject = subject
			found = true
		}
	}
	if !found {
		c.DeviceUserBindings = append(c.DeviceUserBindings, idpregistry.DeviceUserBinding{DeviceID: device, OSPrincipal: testAuthPrincipal, Subject: subject})
	}
	c, err := reg.Upsert(c)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func authTestBindGrant(t *testing.T, g *federatedAuthGate, gr grantstore.Grant) grantstore.Grant {
	t.Helper()
	if gr.DeviceID == "" {
		return gr
	}
	if g.registry == nil {
		g.registry = idpregistry.NewStore()
	}
	c := authTestAssign(t, g.registry, gr.TenantID, gr.DeviceID, gr.UserID, gr.IdPID)
	gr.Issuer = c.Issuer
	gr.OSPrincipal = testAuthPrincipal
	gr.OSSession = testAuthSession
	gr.ProviderConfigSHA256 = authEvidenceForOwner(c, gr.DeviceID, gr.OSPrincipal, gr.OSSession)
	return gr
}
func authTestSignedLink(g *federatedAuthGate, raw string) string {
	u, _ := url.Parse(raw)
	q := u.Query()
	q.Set("os_principal", testAuthPrincipal)
	q.Set("os_session", testAuthSession)
	q.Set("requirements_sig", g.signer.signRequirements(q))
	u.RawQuery = q.Encode()
	return u.String()
}
