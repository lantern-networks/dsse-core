package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestTenantCAPartialWithdrawalBlocksUnrelatedSave(t *testing.T) {
	h, reg, trust, registryPath := tenantCARoutesForTest(t)
	old := tenantCARegistryShared
	tenantCARegistryShared = nil
	defer func() { tenantCARegistryShared = old }()
	var target string
	for _, name := range []string{"outgoing", "replacement"} {
		ca, pem := tenantCATestCA(t, name)
		if name == "outgoing" {
			target = tenantca.CAAnchorKey(ca)
		}
		if w := doTenantCARequest(t, h, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(pem)}); w.Code != 201 {
			t.Fatal(w.Code, w.Body)
		}
	}
	before, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	path := trust.path
	if err = os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	endpoint := "/admin/tenant-cas/tenant_northwind/" + target
	if w := doTenantCARequest(t, h, "DELETE", endpoint, nil); w.Code != 500 {
		t.Fatal(w.Code, w.Body)
	}
	prepared, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	var initialDoc, pendingDoc tenantca.TenantCARegistryFile
	if err = json.Unmarshal(before, &initialDoc); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(prepared, &pendingDoc); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(initialDoc.Tenants, pendingDoc.Tenants) || len(pendingDoc.PendingWithdrawals) != 1 {
		t.Fatal("intent lost original anchors")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	_, peer := tenantCATestCA(t, "peer")
	if w := doTenantCARequest(t, h, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_acme", "ca_pem": string(peer)}); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unrelated save during partial withdrawal returned %d: %s", w.Code, w.Body)
	}
	if w := doTenantCARequest(t, h, "DELETE", "/admin/tenant-cas/tenant_northwind", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatal("whole-tenant removal bypassed incomplete trust withdrawal", w.Code, w.Body)
	}
	for _, managed := range []bool{false, true} {
		called := false
		persist := func(candidate *tenantca.TenantCARegistry) error { called = true; return candidate.Save(registryPath) }
		var e error
		if managed {
			e = reg.ReplaceManagedTenantPersisted("tenant_acme", peer, persist)
		} else {
			e = reg.ReplaceTenantPersisted("tenant_acme", peer, persist)
		}
		if e == nil || called {
			t.Fatal("detached replacement bypassed unfinished withdrawal", managed, e)
		}
	}
	p := &caWithdrawalPersister{data: bytes.Clone(before)}
	if err = reg.SaveTo(p); err == nil || !bytes.Equal(p.data, before) {
		t.Fatal("weak save forgot incomplete withdrawal", err)
	}
	if err = reg.Save(registryPath); err == nil {
		t.Fatal("bare save forgot incomplete withdrawal")
	}
	after, err := os.ReadFile(registryPath)
	if err != nil || !bytes.Equal(prepared, after) {
		t.Fatal("withdrawal recovery target lost", err)
	}
	fresh, err := tenantca.LoadTenantCARegistry(registryPath)
	if !errors.Is(err, tenantca.ErrPendingWithdrawal) || fresh != nil {
		t.Fatal("restart did not refuse the unfinished withdrawal", err)
	}
	if w := doTenantCARequest(t, h, "DELETE", endpoint, nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if len(reg.PendingWithdrawals("")) != 0 {
		t.Fatal("receipt not cleared")
	}
	if w := doTenantCARequest(t, h, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_acme", "ca_pem": string(peer)}); w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	fresh, err = tenantca.LoadTenantCARegistry(registryPath)
	if err != nil || fresh.Registrations()["tenant_northwind"] != 1 || fresh.Registrations()["tenant_acme"] != 1 {
		t.Fatal("retry/peer persistence failed", err)
	}
}
