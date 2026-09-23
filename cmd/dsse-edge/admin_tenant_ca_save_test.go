package main

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestTenantCARegistrationSaveFailureIsPartialAndRetryable(t *testing.T) {
	outbox := &recordingAdminAuditOutboxDeadReader{}
	h, registry, trust, path := tenantCARoutesForTest(t, outbox)
	oldShared := tenantCARegistryShared
	tenantCARegistryShared = nil
	t.Cleanup(func() { tenantCARegistryShared = oldShared })
	cert, pem := tenantCATestCA(t, "Save failure CA")
	// Refuse the atomic rename, after trust and attribution have been applied.
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	body := map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(pem)}
	for attempt := 0; attempt < 3; attempt++ {
		wantStatus, wantResult := http.StatusInternalServerError, "error"
		if attempt == 2 {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			wantStatus, wantResult = http.StatusCreated, "success"
		}
		before := len(outbox.insertedAudits)
		res := doTenantCARequest(t, h, "POST", "/admin/tenant-cas", body)
		if res.Code != wantStatus {
			t.Fatalf("attempt %d: status %d: %s", attempt, res.Code, res.Body)
		}
		var got map[string]any
		if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got["durable"] != (attempt == 2) || got["trusted"] != true {
			t.Fatal(got)
		}
		if attempt < 2 && (got["status"] != "partial" || got["applied"] != true || got["error"] == "") {
			t.Fatal(got)
		}
		if strings.Contains(res.Body.String(), path) {
			t.Fatal("private storage path exposed")
		}
		if !trustStoreHolds(t, trust, cert) || registry.Registrations()["tenant_northwind"] != 1 {
			t.Fatal("partial live state was misreported or duplicate CA added")
		}
		if len(outbox.insertedAudits) != before+2 {
			t.Fatal("missing lifecycle audit")
		}
		if outbox.insertedAudits[before].EventType != "admin_operate_within_tenant" {
			t.Fatal("missing operator audit")
		}
		a := outbox.insertedAudits[before+1]
		if stringPtrValue(a.Result) != wantResult || a.Metadata["durable"] != (attempt == 2) || a.Metadata["actor_admin_principal_id"] != "adm_operator" || a.TenantID != "tenant_northwind" {
			t.Fatalf("wrong audit: %+v", a)
		}
	}
	restarted, err := tenantca.LoadTenantCARegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := restarted.TenantForVerifiedChains([][]*x509.Certificate{{cert}})
	if !ok || owner != "tenant_northwind" {
		t.Fatal("retry did not survive restart", owner)
	}
}
