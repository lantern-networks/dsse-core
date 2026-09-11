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
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/enroll"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// Exercises the REAL POST /enroll handler, not the ledger underneath it, because the property that matters is
// end-to-end: a device an admin disabled must not be handed a certificate, and the refusal must not leak which
// device names exist to a caller who has proved nothing.
func newEnrolTestMux(t *testing.T, token string) (*http.ServeMux, *enrolledinventory.Ledger) {
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
	mux := http.NewServeMux()
	registerEnrollEndpoint(mux, deviceca.NewSigner(caCert, key), ledger, token, "tenant_test", "default", time.Hour, nil)
	return mux, ledger
}

func enrolPost(t *testing.T, mux *http.ServeMux, deviceID, token string) (int, enroll.Response) {
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
	body, _ := json.Marshal(enroll.Request{
		DeviceID:    deviceID,
		CSRPEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		Eligibility: enroll.Eligibility{Mode: "token", Token: token},
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enroll", bytes.NewReader(body)))
	var resp enroll.Response
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp
}

func TestEnrollRefusesADeviceAnAdminDisabled(t *testing.T) {
	const token = "eligible"
	mux, ledger := newEnrolTestMux(t, token)
	const id = "dev-disabled"

	if code, resp := enrolPost(t, mux, id, token); code != http.StatusOK || resp.CertPEM == "" {
		t.Fatalf("first enrolment must issue: code=%d err=%q", code, resp.Error)
	}
	if _, ok := ledger.SetEnabled(id, false, time.Now().UTC().Format(time.RFC3339)); !ok {
		t.Fatalf("disable must find the entry")
	}

	// Same name, same valid credential. No certificate may come back.
	code, resp := enrolPost(t, mux, id, token)
	if code != http.StatusForbidden {
		t.Fatalf("re-enrolment of a disabled device must be refused, got %d", code)
	}
	if resp.CertPEM != "" {
		t.Fatalf("a refused enrolment must not return a certificate")
	}
	if resp.Error != "identity is disabled by an administrator" {
		t.Fatalf("the operator deserves the real reason, got %q", resp.Error)
	}
	if ledger.IsAdmitted(id) {
		t.Fatalf("the device must stay out of the ledger's admitted set")
	}
}

// The refusal must not become an oracle. A caller with no valid credential gets the SAME answer whether the name
// is disabled, already enrolled, or has never been seen — otherwise POST /enroll, which is public and
// unauthenticated by construction, would enumerate a tenant's device inventory for anyone who asks.
func TestEnrollDoesNotRevealWhichNamesAreDisabled(t *testing.T) {
	const token = "eligible"
	mux, ledger := newEnrolTestMux(t, token)

	if code, _ := enrolPost(t, mux, "dev-known", token); code != http.StatusOK {
		t.Fatalf("setup enrolment failed: %d", code)
	}
	ledger.SetEnabled("dev-known", false, time.Now().UTC().Format(time.RFC3339))
	if code, _ := enrolPost(t, mux, "dev-live", token); code != http.StatusOK {
		t.Fatalf("setup enrolment failed: %d", code)
	}

	var answers []string
	for _, name := range []string{"dev-known", "dev-live", "dev-never-seen"} {
		code, resp := enrolPost(t, mux, name, "wrong-token")
		if code != http.StatusForbidden {
			t.Fatalf("%s: an invalid credential must be refused, got %d", name, code)
		}
		answers = append(answers, resp.Error)
	}
	for i, got := range answers {
		if got != answers[0] {
			t.Fatalf("answer %d differs (%q vs %q) — the refusal distinguishes device states to an "+
				"unauthenticated caller, which enumerates the inventory", i, got, answers[0])
		}
	}
}

// ★ RE-ENROLLING AN IDENTITY THAT ALREADY HAS A CERTIFICATE IS REFUSED (2026-08-12, twentieth review), and
// this test used to assert the opposite.
//
// The old reasoning was operational and real: a re-image, a lost key, a reinstall. What it missed is that an
// enrolment token is one-time and NOT bound to a device id — nothing in the token names one, and the Console
// cannot know the id before the machine is set up. So "an enabled device may enrol again" reads, from the
// other side, as "any holder of a valid credential for this tenant may obtain a certificate in the name of any
// machine in it". The cross-tenant guard never fires, because it is the same tenant.
//
// Nothing in the protocol distinguishes a re-image from an impersonation; only a person can. So the way back
// is the person: an administrator re-adds the device, which clears the marker, and the machine enrols once
// more. Authenticated, audited, and a decision somebody made.
func TestAnIdentityThatHasEnrolledCannotEnrolAgainUntilAnAdminSaysSo(t *testing.T) {
	const token = "eligible"
	mux, ledger := newEnrolTestMux(t, token)
	if code, _ := enrolPost(t, mux, "dev-reimage", token); code != http.StatusOK {
		t.Fatalf("first enrolment failed")
	}

	code, resp := enrolPost(t, mux, "dev-reimage", token)

	if code == http.StatusOK || resp.CertPEM != "" {
		t.Fatalf("a second enrolment of an identity that already holds a certificate succeeded (code=%d, "+
			"%d bytes of certificate) — that is a certificate in an existing machine's name, issued to whoever "+
			"holds a token for the tenant", code, len(resp.CertPEM))
	}

	// The operator's decision re-arms it — and it is its OWN operation, not a side effect of re-adding the
	// device: an admin fixing a note or assigning a group must not silently re-open enrolment.
	if _, _, err := ledger.AllowReenrolment("dev-reimage", "", "2026-08-12T00:00:00Z"); err != nil {
		t.Fatalf("an admin could not permit a re-imaged device to enrol again: %v", err)
	}
	if code, resp := enrolPost(t, mux, "dev-reimage", token); code != http.StatusOK || resp.CertPEM == "" {
		t.Fatalf("after the admin re-added it, the re-imaged device still could not enrol: code=%d err=%q",
			code, resp.Error)
	}
}
