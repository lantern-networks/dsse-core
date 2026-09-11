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
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/enroll"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// ★★★ A REFUSED ENROLMENT WAS SPENDING THE ADMINISTRATOR'S ONE-TIME APPROVAL (2026-08-29, measured on Windows
// by the session that walked the install lane there and confirmed twice in its ledger).
//
// The endpoint spends the token in Assign and reaches "this identity is already enrolled" in Record, so the
// approval was gone by the time the device was turned away. What made it expensive is the second attempt: with
// the token spent, the same device is refused with "invalid or missing eligibility token" — a different
// problem, named confidently — and the operator issues another token, and another, never reaching the
// re-enrolment grant that actually fixes it. The true refusal is seen exactly once.
func newOneTimeTokenEnrolMux(t *testing.T) (*http.ServeMux, *enrolledinventory.Ledger, *enrolltoken.Store) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test device CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	ledger := enrolledinventory.NewLedger()
	tokens := enrolltoken.NewStore()
	mux := http.NewServeMux()
	registerEnrollEndpointWithIdP(mux, deviceca.NewSigner(caCert, key), ledger, tokens, nil,
		"", "tenant_test", "default", time.Hour, nil, nil, nil, nil, nil)
	return mux, ledger, tokens
}

func mintOneTimeToken(t *testing.T, tokens *enrolltoken.Store) string {
	t.Helper()
	now := time.Now().UTC()
	_, secret, err := tokens.Issue(enrolltoken.Policy{}, "tenant_test", "default", "a device", "admin", "admin",
		now.Add(24*time.Hour), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return secret
}

func enrolWithOneTimeToken(t *testing.T, mux *http.ServeMux, deviceID, secret string) (int, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: deviceID}}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, err := json.Marshal(enroll.Request{
		DeviceID:    deviceID,
		CSRPEM:      string(csr),
		Eligibility: enroll.Eligibility{Mode: "token", Token: secret},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/enroll", bytes.NewReader(body)))
	// The refusal text is what an operator reads, so the test reads the same thing rather than a field only
	// the happy path has.
	return rec.Code, rec.Body.String()
}

func TestARefusedEnrolmentLeavesTheOneTimeApprovalUnspent(t *testing.T) {
	mux, _, tokens := newOneTimeTokenEnrolMux(t)

	first := mintOneTimeToken(t, tokens)
	if code, _ := enrolWithOneTimeToken(t, mux, "already-there", first); code != http.StatusOK {
		t.Fatalf("the first enrolment should succeed, got %d", code)
	}

	// The same name again — a machine that was re-imaged, which is the case an operator actually meets.
	second := mintOneTimeToken(t, tokens)
	code, said := enrolWithOneTimeToken(t, mux, "already-there", second)
	if code == http.StatusOK {
		t.Fatal("a second enrolment under the same name was allowed")
	}

	// The refusal must be the TRUE one, not the one the spend causes.
	if strings.Contains(said, "invalid or missing eligibility token") {
		t.Fatalf("the refusal names the token, not the reason: %s", said)
	}
	if !strings.Contains(said, "already enrolled") {
		t.Fatalf("the refusal does not say what is actually wrong: %s", said)
	}

	// And the approval must still be there. This is the assertion that fails on the old order.
	if n := tokens.Outstanding("tenant_test", time.Now().UTC()); n != 1 {
		t.Fatalf("the refused enrolment spent the administrator's approval: %d outstanding, want 1", n)
	}

}

func TestTheSurvivingTokenStillWorksAfterTheGrant(t *testing.T) {
	mux, ledger, tokens := newOneTimeTokenEnrolMux(t)
	first := mintOneTimeToken(t, tokens)
	if code, _ := enrolWithOneTimeToken(t, mux, "reimaged", first); code != http.StatusOK {
		t.Fatalf("first enrolment: %d", code)
	}
	second := mintOneTimeToken(t, tokens)
	if code, _ := enrolWithOneTimeToken(t, mux, "reimaged", second); code == http.StatusOK {
		t.Fatal("the second enrolment should have been refused")
	}
	// The administrator's grant — the thing the operator should have reached the first time.
	if _, _, err := ledger.AllowReenrolment("reimaged", "tenant_test", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("allow re-enrolment: %v", err)
	}
	// The SAME token, never spent, now works.
	if code, said := enrolWithOneTimeToken(t, mux, "reimaged", second); code != http.StatusOK {
		t.Fatalf("the surviving approval did not work after the grant: %d %s", code, said)
	}
}
