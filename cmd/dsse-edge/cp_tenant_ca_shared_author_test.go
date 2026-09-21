package main

import (
	"bytes"
	"os"
	"testing"
)

func TestPostgresCAAuthorTermReadAndWholeWithdrawal(t *testing.T) {
	leader, peer := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "tenant_ca_registry"}
	saved, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	defer func() {
		if saved == nil {
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
		} else {
			p.Save(saved)
		}
	}()
	a, reg, _, _ := tenantCARoutesForTest(t)
	oldP, oldCP, oldE := tenantCARegistryShared, edgeIsControlPlane, cpLeaderElectorInstance
	defer func() { tenantCARegistryShared = oldP; edgeIsControlPlane = oldCP; cpLeaderElectorInstance = oldE }()
	gate := &runtimeLeaseGate{postgresBlobPersister: p}
	tenantCARegistryShared = gate
	edgeIsControlPlane = true
	deviceClientCAs = nil
	cpLeaderElectorInstance = nil
	_, own := tenantCATestCA(t, "Own")
	_, foreign := tenantCATestCA(t, "Foreign")
	for tenant, pem := range map[string][]byte{"tenant_northwind": own, "tenant_acme": foreign} {
		r := doTenantCARequest(t, a, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": tenant, "ca_pem": string(pem)})
		if r.Code != 201 {
			t.Fatal(r.Code, r.Body)
		}
	}
	before, _ := p.Load()
	live, _ := reg.Snapshot()
	cpLeaderElectorInstance = leader
	leader.tick()
	if !leader.IsLeader() {
		t.Fatal("leader")
	}
	gate.before = func() {
		leader.release()
		peer.tick()
		if !peer.IsLeader() {
			t.Fatal("peer")
		}
		peer.release()
		leader.tick()
	}
	r := doTenantCARequest(t, a, "DELETE", "/admin/tenant-cas/tenant_northwind", nil)
	if r.Code != 503 {
		t.Fatal(r.Code, r.Body)
	}
	gate.before = nil
	after, _ := p.Load()
	liveAfter, _ := reg.Snapshot()
	if !bytes.Equal(before, after) || !bytes.Equal(live, liveAfter) {
		t.Fatal("old request mutated shared or live registry")
	}
	r = doTenantCARequest(t, a, "DELETE", "/admin/tenant-cas/tenant_northwind", nil)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	if reg.Registrations()["tenant_northwind"] != 0 || reg.Registrations()["tenant_acme"] != 1 {
		t.Fatal(reg.Registrations())
	}
	after, _ = p.Load()
	for _, bad := range [][]byte{[]byte(`{}`), []byte(`{"tenants":[{"tenant_id":"x","ca_pem":"bad"}]}`)} {
		p.Save(bad)
		r = doTenantCARequest(t, a, "GET", "/admin/tenant-cas", nil)
		if r.Code != 503 {
			t.Fatal(r.Code, r.Body)
		}
		r = doTenantCARequest(t, a, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(own)})
		if r.Code != 503 {
			t.Fatal(r.Code, r.Body)
		}
		got, _ := p.Load()
		if !bytes.Equal(got, bad) {
			t.Fatal("corrupt row overwritten")
		}
	}
	db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
	r = doTenantCARequest(t, a, "GET", "/admin/tenant-cas", nil)
	if r.Code != 503 {
		t.Fatal(r.Code, r.Body)
	}
	r = doTenantCARequest(t, a, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(own)})
	if r.Code != 503 {
		t.Fatal(r.Code, r.Body)
	}
	p.Save(after)
	r = doTenantCARequest(t, a, "GET", "/admin/tenant-cas", nil)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	generation := reg.ConfigGeneration()
	doTenantCARequest(t, a, "GET", "/admin/tenant-cas", nil)
	if generation != reg.ConfigGeneration() {
		t.Fatal("unchanged read advanced generation")
	}
	r = doTenantCARequest(t, a, "DELETE", "/admin/tenant-cas/tenant_acme", nil)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	r = doTenantCARequest(t, a, "GET", "/admin/tenant-cas", nil)
	if r.Code != 200 || len(reg.Registrations()) != 0 {
		t.Fatal("empty snapshot was not adopted", r.Code, r.Body)
	}
}
