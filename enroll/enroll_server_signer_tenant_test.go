package enroll

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lantern-networks/dsse-core/deviceca"
)

func TestEnrolmentDoesNotFallBackToAnotherTenantsCA(t *testing.T) {
	defaultSigner, _ := newDeviceCASigner(t)
	_, csr, err := GenerateKeyAndCSR("device-b", "tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(Request{DeviceID: "device-b", Tenant: "tenant-b", CSRPEM: string(csr)})
	if err != nil {
		t.Fatal(err)
	}
	issued := 0
	issuer := Issuer{
		Signer: defaultSigner, // tenant-a's legacy signer must not issue for B
		SignerFor: func(tenant string) *deviceca.Signer {
			if tenant != "tenant-b" {
				t.Fatalf("unexpected assigned tenant %q", tenant)
			}
			return nil
		},
		Assign: func(Request) (string, string, string, bool) { return "tenant-b", "", "", true },
		Record: func(string, string, string) error { issued++; return nil },
	}
	w := httptest.NewRecorder()
	issuer.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("tenant-b enrolment used tenant-a signer: status %d", w.Code)
	}
	if issued != 0 {
		t.Fatal("refused enrolment was recorded")
	}

	// A missing issuer without a per-tenant selector must fail safely too.
	issuer.Signer, issuer.SignerFor = nil, nil
	w = httptest.NewRecorder()
	issuer.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body)))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing signer status %d, want 503", w.Code)
	}
}
