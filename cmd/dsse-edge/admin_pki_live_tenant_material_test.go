package main

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestPKIInventoryFollowsInstalledTenantMaterialAndWithdrawals(t *testing.T) {
	isolatedDeviceAuthorityPools(t)
	reg := tenantca.NewTenantCARegistry()
	old, oldPEM, oldKey := deviceAdmissionTestCA(t, "same CA name")
	next, nextPEM, nextKey := deviceAdmissionTestCA(t, "same CA name")
	byo, byoPEM, _ := deviceAdmissionTestCA(t, "BYO")
	transport := newTransportTenantCerts()
	pair := deviceLeafForCA(t, old, oldKey)
	pair.Leaf, _ = x509.ParseCertificate(pair.Certificate[0])
	now := time.Now()
	transport.put("tenant_a", []string{"a.example.invalid", "enrol.a.example.invalid"}, &pair, string(oldPEM), now.Add(time.Hour))
	install := func(caPEM string, mat tenantDeviceMaterial) {
		t.Helper()
		mat.AdmissionCAPEM = caPEM
		if err := tenantDeviceIdentity.Install(mat, reg, nil); err != nil {
			t.Fatal(err)
		}
	}
	install(string(oldPEM)+string(byoPEM), deviceMaterialForCA(t, "tenant_a", old, oldKey, string(oldPEM)))
	count := func(items []pkiCertificateItem, fp, role string) int {
		n := 0
		for _, v := range items {
			if v.SHA256 == fp && v.Role == role {
				n++
				if v.TenantID != "tenant_a" {
					t.Fatal("lost registry/selector ownership")
				}
				if strings.Contains(strings.Join(v.Capabilities, ","), "retire") {
					t.Fatal("offered generic deletion of CP-distributed authority")
				}
			}
		}
		return n
	}
	items := liveTenantPKICertificateItems(transport, tenantDeviceIdentity, reg, now)
	if count(items, certFingerprint(old), "device_issuing_ca") != 1 || count(items, certFingerprint(byo), "device_client_ca") != 1 {
		t.Fatal("installed managed/BYO authorities absent")
	}
	if count(items, certFingerprint(pair.Leaf), "transport_server") != 1 {
		t.Fatal("SNI aliases duplicated or hid the served leaf")
	}
	for _, item := range items {
		hasRenew := strings.Contains(strings.Join(item.Capabilities, ","), "renew_all")
		if hasRenew != (item.Role == "device_issuing_ca") {
			t.Fatalf("renewal capability must follow the installed issuer: role=%s capabilities=%v", item.Role, item.Capabilities)
		}
		if item.Role == "transport_server" && len(item.PresentedAt) != 2 {
			t.Fatal("actual selected names absent")
		}
	}
	install(string(nextPEM)+string(byoPEM), deviceMaterialForCA(t, "tenant_a", next, nextKey, string(nextPEM)))
	items = liveTenantPKICertificateItems(transport, tenantDeviceIdentity, reg, now)
	if count(items, certFingerprint(old), "device_issuing_ca") != 0 || count(items, certFingerprint(next), "device_issuing_ca") != 1 || count(items, certFingerprint(byo), "device_client_ca") != 1 {
		t.Fatal("inventory did not follow managed retirement while retaining BYO")
	}
	install(string(nextPEM), deviceMaterialForCA(t, "tenant_a", next, nextKey, string(nextPEM)))
	items = liveTenantPKICertificateItems(transport, tenantDeviceIdentity, reg, now)
	if count(items, certFingerprint(byo), "device_client_ca") != 0 {
		t.Fatal("withdrawn BYO still appears admitted")
	}
	for _, item := range liveTenantPKICertificateItems(transport, tenantDeviceIdentity, reg, now.Add(2*time.Hour)) {
		if item.Role == "transport_server" && item.Active {
			t.Fatal("expired selector appears active")
		}
	}
	scoped := pkiCertificateItemsForTenant(items, "tenant_other", nil)
	if len(scoped) != 0 {
		t.Fatal("tenant runtime material leaked into another organization's screen")
	}
	inv := mergeLiveTenantPKIInventory(pkiCertificateInventory{Items: []pkiCertificateItem{{Role: "device_client_ca", SHA256: certFingerprint(next), Capabilities: []string{"retire"}}}}, items)
	if count(inv.Items, certFingerprint(next), "device_issuing_ca") != 1 || count(inv.Items, certFingerprint(next), "device_client_ca") != 0 {
		t.Fatal("startup and runtime views duplicated a managed CA")
	}
}
