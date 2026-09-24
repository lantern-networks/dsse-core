package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/tenantca"
	"os"
	"testing"
)

func TestTenantCAFilePendingWithdrawalBlocksRestart(t *testing.T) {
	out := &recordingAdminAuditOutboxDeadReader{}
	h, reg, trust, path := tenantCARoutesForTest(t, out)
	old := tenantCARegistryShared
	tenantCARegistryShared = nil
	defer func() { tenantCARegistryShared = old }()
	var fp string
	for i := 0; i < 2; i++ {
		c, pem := tenantCATestCA(t, fmt.Sprint("restart-", i))
		if i == 0 {
			fp = tenantca.CAAnchorKey(c)
		}
		r := doTenantCARequest(t, h, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(pem)})
		if r.Code != 201 {
			t.Fatal(r.Code, r.Body)
		}
	}
	endpoint := "/admin/tenant-cas/tenant_northwind/" + fp
	if err := os.Rename(trust.path, trust.path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(trust.path, 0700); err != nil {
		t.Fatal(err)
	}
	r := doTenantCARequest(t, h, "DELETE", endpoint, nil)
	if r.Code != 500 {
		t.Fatal(r.Code, r.Body)
	}
	if len(reg.PendingWithdrawals("tenant_northwind")) != 1 {
		t.Fatal("missing pending target")
	}
	if fresh, err := tenantca.LoadTenantCARegistry(path); !errors.Is(err, tenantca.ErrPendingWithdrawal) || fresh != nil {
		t.Fatalf("restart did not reject unfinished withdrawal: registry=%v err=%v", fresh, err)
	}
	// A retry cannot relabel an already-applied partial withdrawal as not started.
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	r = doTenantCARequest(t, h, "DELETE", endpoint, nil)
	if r.Code != 500 || !bytes.Contains(r.Body.Bytes(), []byte(`"applied":true`)) {
		t.Fatal(r.Code, r.Body)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(trust.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(trust.path+".saved", trust.path); err != nil {
		t.Fatal(err)
	}
	r = doTenantCARequest(t, h, "DELETE", endpoint, nil)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	fresh, err := tenantca.LoadTenantCARegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Registrations()["tenant_northwind"] != 1 || trustStoreHoldsAnchor(trust, fp) {
		t.Fatal("retry did not finish")
	}
}

func TestTenantCAWithdrawalIntentFailureDoesNotApply(t *testing.T) {
	out := &recordingAdminAuditOutboxDeadReader{}
	h, reg, trust, path := tenantCARoutesForTest(t, out)
	old := tenantCARegistryShared
	tenantCARegistryShared = nil
	defer func() { tenantCARegistryShared = old }()
	var fp string
	for i := 0; i < 2; i++ {
		c, pem := tenantCATestCA(t, fmt.Sprint("intent-", i))
		if i == 0 {
			fp = tenantca.CAAnchorKey(c)
		}
		r := doTenantCARequest(t, h, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(pem)})
		if r.Code != 201 {
			t.Fatal(r.Code, r.Body)
		}
	}
	before, err := os.ReadFile(trust.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	endpoint := "/admin/tenant-cas/tenant_northwind/" + fp
	r := doTenantCARequest(t, h, "DELETE", endpoint, nil)
	if r.Code != 503 {
		t.Fatal(r.Code, r.Body)
	}
	after, err := os.ReadFile(trust.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || reg.Registrations()["tenant_northwind"] != 2 || !trustStoreHoldsAnchor(trust, fp) {
		t.Fatal("unconfirmed intent changed admission")
	}
	found := false
	for _, a := range out.insertedAudits {
		if a.Action != nil && *a.Action == "tenant_ca_anchor_withdraw" {
			found = true
			if stringPtrValue(a.Result) != "error" || a.Metadata["applied"] != false {
				t.Fatal(a)
			}
		}
	}
	if !found {
		t.Fatal("missing failed-intent audit")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	r = doTenantCARequest(t, h, "DELETE", endpoint, nil)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	if _, err = tenantca.LoadTenantCARegistry(path); err != nil {
		t.Fatal(err)
	}
}
