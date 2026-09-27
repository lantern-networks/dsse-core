package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/lantern-networks/dsse-core/tenantca"
)

type caWithdrawalPersister struct {
	data []byte
	fail bool
}

func (p *caWithdrawalPersister) Load() ([]byte, error) { return p.data, nil }
func (p *caWithdrawalPersister) Save(b []byte) error {
	if p.fail {
		return fmt.Errorf("synthetic save failure")
	}
	p.data = bytes.Clone(b)
	return nil
}

func TestTenantCAWithdrawalRetryKeepsRemoval(t *testing.T) {
	for _, single := range []bool{false, true} {
		t.Run(fmt.Sprint(single), func(t *testing.T) {
			out := &recordingAdminAuditOutboxDeadReader{}
			h, reg, _, _ := tenantCARoutesForTest(t, out)
			p := &caWithdrawalPersister{}
			old := tenantCARegistryShared
			tenantCARegistryShared = p
			defer func() { tenantCARegistryShared = old }()
			ca, pem := tenantCATestCA(t, "Retire CA")
			_, keep := tenantCATestCA(t, "Keep CA")
			for _, x := range []struct {
				tenant string
				pem    []byte
			}{{"tenant_northwind", pem}, {"tenant_acme", keep}} {
				res := doTenantCARequest(t, h, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": x.tenant, "ca_pem": string(x.pem)})
				if res.Code != 201 {
					t.Fatal(res.Code, res.Body)
				}
			}
			if single {
				_, extra := tenantCATestCA(t, "Remaining own CA")
				res := doTenantCARequest(t, h, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(extra)})
				if res.Code != 201 {
					t.Fatal(res.Code, res.Body)
				}
			}
			wantRemaining := 0
			if single {
				wantRemaining = 1
			}
			path := "/admin/tenant-cas/tenant_northwind"
			if single {
				path += "/" + tenantca.CAAnchorKey(ca)
			}
			before := bytes.Clone(p.data)
			p.fail = true
			for i := 0; i < 2; i++ {
				res := doTenantCARequest(t, h, "DELETE", path, nil)
				if res.Code != http.StatusInternalServerError {
					t.Fatalf("attempt%d: %d %s", i, res.Code, res.Body)
				}
				if _, err := reg.LoadFrom(p); err != nil {
					t.Fatal(err)
				}
				if _, err := reg.Register("tenant_northwind", pem); err == nil {
					t.Fatal("pending withdrawal re-registered")
				}
				if !bytes.Equal(before, p.data) || reg.Registrations()["tenant_northwind"] != wantRemaining {
					t.Fatal("partial state wrong")
				}
			}
			p.fail = false
			res := doTenantCARequest(t, h, "DELETE", path, nil)
			if res.Code != 200 {
				t.Fatal(res.Code, res.Body)
			}
			fresh := tenantca.NewTenantCARegistry()
			if _, err := fresh.LoadFrom(p); err != nil {
				t.Fatal(err)
			}
			if fresh.Registrations()["tenant_northwind"] != wantRemaining || fresh.Registrations()["tenant_acme"] != 1 {
				t.Fatal("withdrawal resurrected or peer lost")
			}
			var results []string
			for _, a := range out.insertedAudits {
				if a.Action != nil && (*a.Action == "tenant_ca_withdraw" || *a.Action == "tenant_ca_anchor_withdraw") {
					results = append(results, stringPtrValue(a.Result))
				}
			}
			if fmt.Sprint(results) != "[error error success]" {
				t.Fatal("audit results", results)
			}
		})
	}
}

func TestTenantCATrustWithdrawalFailureRemainsRetryable(t *testing.T) {
	out := &recordingAdminAuditOutboxDeadReader{}
	h, reg, trust, _ := tenantCARoutesForTest(t, out)
	old := tenantCARegistryShared
	tenantCARegistryShared = nil
	defer func() { tenantCARegistryShared = old }()
	var fingerprint string
	for i := 0; i < 2; i++ {
		cert, pem := tenantCATestCA(t, fmt.Sprintf("Trust retry %d", i))
		if i == 0 {
			fingerprint = tenantca.CAAnchorKey(cert)
		}
		res := doTenantCARequest(t, h, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(pem)})
		if res.Code != 201 {
			t.Fatal(res.Code, res.Body)
		}
	}
	path := trust.path
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	endpoint := "/admin/tenant-cas/tenant_northwind/" + fingerprint
	res := doTenantCARequest(t, h, "DELETE", endpoint, nil)
	if res.Code != 500 {
		t.Fatal(res.Code, res.Body)
	}
	if len(reg.PendingWithdrawals("tenant_northwind")) != 1 || !trustStoreHoldsAnchor(trust, fingerprint) {
		t.Fatal("trust partial state misreported")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	res = doTenantCARequest(t, h, "DELETE", endpoint, nil)
	if res.Code != 200 {
		t.Fatal(res.Code, res.Body)
	}
	if len(reg.PendingWithdrawals("tenant_northwind")) != 0 || trustStoreHoldsAnchor(trust, fingerprint) {
		t.Fatal("trust retry not completed")
	}
}
