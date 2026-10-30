package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestDeviceAuthorityReadUsesExactOrganizationID(t *testing.T) {
	a := newTenantDeviceAuthority(nil, nil, time.Now)
	if _, err := a.EnsureCA("TenantA", "a"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	admin := func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }
	registerTenantAuthorityReadRoutes(mux, admin, a, nil)
	r := httptest.NewRequest(http.MethodGet, "/admin/tenant-device-authority", nil)
	r = requestWithAdminIdentity(r, adminIdentity{PrincipalID: "admin", TenantID: "TenantA"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var answer struct {
		HasAuthority bool `json:"has_authority"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &answer) != nil || !answer.HasAuthority {
		t.Fatalf("exact organization authority was reported absent: status=%d", w.Code)
	}
}

func TestDeviceCAReparentCandidatesExcludeCaseDistinctOrganization(t *testing.T) {
	upperCA, upperPEM, _ := deviceAdmissionTestCA(t, "upper tenant")
	_, lowerPEM, _ := deviceAdmissionTestCA(t, "lower tenant")
	reg := tenantca.NewTenantCARegistry()
	if _, err := reg.Register("TenantA", upperPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Register("tenanta", lowerPEM); err != nil {
		t.Fatal(err)
	}
	got := deviceCACertificatesForTenant(serverConfig{TenantCARegistry: reg}, "TenantA")
	if len(got) != 1 || certFingerprint(got[0]) != certFingerprint(upperCA) {
		t.Fatal("another organization's CA was considered a reparent candidate")
	}
}

func TestDeviceRotationDoesNotCountCaseDistinctTenantsCAAsOwn(t *testing.T) {
	oldSigners, oldFacts := tenantDeviceIdentity, deviceCertificates
	t.Cleanup(func() { tenantDeviceIdentity, deviceCertificates = oldSigners, oldFacts })
	otherCA, otherPEM, _ := deviceAdmissionTestCA(t, "other tenant")
	reg := tenantca.NewTenantCARegistry()
	if _, err := reg.Register("tenanta", otherPEM); err != nil {
		t.Fatal(err)
	}
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("device-one", "TenantA", "", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	tenantDeviceIdentity = &tenantDeviceSigners{rotation: map[string]deviceAuthorityFingerprints{
		"TenantA": {SignerSHA256: dcaNew, OutgoingSHA256: dcaOld},
	}}
	deviceCertificates = &deviceCertificateFacts{by: map[string]deviceCertificateFact{
		"device-one": {Identity: "device-one", AnchorSHA256: certFingerprint(otherCA), TenantID: "TenantA"},
	}}
	mux := http.NewServeMux()
	admin := func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }
	registerDeviceAuthorityRotationRoute(mux, admin, serverConfig{EnrolledLedger: ledger, TenantCARegistry: reg})
	r := httptest.NewRequest(http.MethodGet, "/admin/device-authority-rotation", nil)
	r = requestWithAdminIdentity(r, adminIdentity{PrincipalID: "admin", TenantID: "TenantA"})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var answer deviceAuthorityRotationReadiness
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &answer) != nil {
		t.Fatalf("rotation status=%d", w.Code)
	}
	if answer.MayRetirePrevious || len(answer.OnSomethingElse) != 1 ||
		strings.Join(answer.OnAnotherOfTheirOwn, ",") != "" {
		t.Fatal("case-distinct organization's CA incorrectly opened the retirement gate")
	}
}
