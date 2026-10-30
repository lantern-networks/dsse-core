package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

func TestRenewalRequiresTheExactTenantAuthority(t *testing.T) {
	nodeCA, nodeKey, _ := graceTestCA(t)
	otherCA, otherKey, _ := graceTestCA(t)
	nodeSigner := deviceca.NewSigner(nodeCA, nodeKey)
	otherSigner := deviceca.NewSigner(otherCA, otherKey)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "untrusted-csr-subject", Organization: []string{"untrusted"}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"csr_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))})
	if err != nil {
		t.Fatal(err)
	}
	previous := tenantDeviceIdentity
	t.Cleanup(func() { tenantDeviceIdentity = previous })
	for _, tc := range []struct {
		name, deviceTenant string
		managed            map[string]*deviceca.Signer
		wantCode           int
		issuer             *x509.Certificate
	}{
		{"own-node-authority", "Acme", nil, http.StatusOK, nodeCA},
		{"other-tenant-without-authority", "Other", nil, http.StatusServiceUnavailable, nil},
		{"case-distinct-node-tenant", "acme", nil, http.StatusServiceUnavailable, nil},
		{"managed-owner", "Other", map[string]*deviceca.Signer{"Other": otherSigner}, http.StatusOK, otherCA},
		{"case-distinct-managed-tenant", "Acme", map[string]*deviceca.Signer{"acme": otherSigner}, http.StatusOK, nodeCA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tenantDeviceIdentity = &tenantDeviceSigners{signers: tc.managed}
			ledger := enrolledinventory.NewLedger()
			ledger.ReplaceAll([]enrolledinventory.Entry{{Identity: "verified-device", TenantID: tc.deviceTenant, Enabled: true}}, "")
			mux := http.NewServeMux()
			registerEnrollRenewEndpointWithIdentity(mux, nodeSigner, ledger, "Acme", time.Hour,
				func(*http.Request) (string, bool) { return "verified-device", true }, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enroll/renew", bytes.NewReader(body)))
			if rec.Code != tc.wantCode {
				t.Fatalf("renewal status=%d, want=%d", rec.Code, tc.wantCode)
			}
			var response renewResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if tc.issuer == nil {
				if response.CertPEM != "" || response.CAPEM != "" {
					t.Fatal("refused renewal returned certificate material")
				}
				return
			}
			block, _ := pem.Decode([]byte(response.CertPEM))
			if block == nil {
				t.Fatal("successful renewal returned no certificate")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := cert.CheckSignatureFrom(tc.issuer); err != nil {
				t.Fatal("renewed under a different tenant's authority")
			}
			if cert.Subject.CommonName != "verified-device" || len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != tc.deviceTenant {
				t.Fatal("renewed subject does not match the authoritative identity and tenant")
			}
		})
	}
}
