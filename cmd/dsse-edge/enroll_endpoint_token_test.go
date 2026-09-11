package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// Drives the REAL POST /enroll handler with admin-issued tokens, because the properties that matter are
// end-to-end: one machine per token, no certificate for a spent or expired one, and refusals that do not tell an
// unauthenticated caller which tokens exist.
func newTokenEnrolTestMux(t *testing.T) (*http.ServeMux, *enrolltoken.Store, *enrolledinventory.Ledger) {
	t.Helper()
	return newTokenEnrolTestMuxWith(t, enrolledinventory.NewLedger(), nil)
}

// newTokenEnrolTestMuxWith lets a test supply the ledger and the licensing gate, so the licensing tests exercise
// the same real endpoint rather than a parallel wiring that could drift from it.
func newTokenEnrolTestMuxWith(t *testing.T, ledger *enrolledinventory.Ledger, licensing EnrolmentLicensing) (*http.ServeMux, *enrolltoken.Store, *enrolledinventory.Ledger) {
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
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	tokens := enrolltoken.NewStore()
	mux := http.NewServeMux()
	// No shared token: that is the deployment this replaces.
	registerEnrollEndpointWithIdP(mux, deviceca.NewSigner(caCert, key), ledger, tokens, licensing, "", "tenant_test", "default", time.Hour, nil, nil, nil, nil, nil)
	return mux, tokens, ledger
}

func mintToken(t *testing.T, s *enrolltoken.Store, life time.Duration) string {
	t.Helper()
	now := time.Now().UTC()
	_, secret, err := s.Issue(enrolltoken.DefaultPolicy(), "tenant_test", "", "kitting", "adm_alice", "", now.Add(life), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return secret
}

func TestAnAdminIssuedTokenEnrolsExactlyOneMachine(t *testing.T) {
	mux, tokens, ledger := newTokenEnrolTestMux(t)
	secret := mintToken(t, tokens, 72*time.Hour)

	code, resp := enrolPost(t, mux, "laptop-01", secret)
	if code != http.StatusOK || resp.CertPEM == "" {
		t.Fatalf("a valid token must issue a certificate: code=%d err=%q", code, resp.Error)
	}
	if !ledger.IsAdmitted("laptop-01") {
		t.Fatalf("the enrolled device must be admitted")
	}

	// The installer config gets copied to a second machine. That is the whole reason one-time exists.
	code, resp = enrolPost(t, mux, "laptop-02", secret)
	if code != http.StatusForbidden || resp.CertPEM != "" {
		t.Fatalf("a spent token must not enrol a second machine: code=%d cert=%d", code, len(resp.CertPEM))
	}
	if ledger.IsAdmitted("laptop-02") {
		t.Fatalf("the second machine must not be in the ledger")
	}
}

func TestAnExpiredTokenEnrolsNothing(t *testing.T) {
	mux, tokens, _ := newTokenEnrolTestMux(t)
	now := time.Now().UTC()
	_, secret, err := tokens.Issue(enrolltoken.DefaultPolicy(), "tenant_test", "", "", "adm_alice", "", now.Add(time.Millisecond), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if code, resp := enrolPost(t, mux, "laptop-late", secret); code != http.StatusForbidden || resp.CertPEM != "" {
		t.Fatalf("an expired token must not issue: code=%d", code)
	}
}

func TestARevokedTokenEnrolsNothing(t *testing.T) {
	mux, tokens, _ := newTokenEnrolTestMux(t)
	now := time.Now().UTC()
	tok, secret, err := tokens.Issue(enrolltoken.DefaultPolicy(), "tenant_test", "", "", "adm_alice", "", now.Add(72*time.Hour), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	tokens.Revoke(tok.ID, "adm_alice", now)
	if code, resp := enrolPost(t, mux, "laptop-astray", secret); code != http.StatusForbidden || resp.CertPEM != "" {
		t.Fatalf("a revoked token must not issue: code=%d", code)
	}
}

// Which of "never existed", "already spent", "expired" and "revoked" is true would let anyone probe a tenant's
// issuance state from a public endpoint. All four must read identically to the caller.
func TestTokenRefusalsAreIndistinguishable(t *testing.T) {
	mux, tokens, _ := newTokenEnrolTestMux(t)
	now := time.Now().UTC()

	spent := mintToken(t, tokens, 72*time.Hour)
	if code, _ := enrolPost(t, mux, "laptop-01", spent); code != http.StatusOK {
		t.Fatalf("setup enrolment failed: %d", code)
	}
	killedTok, killed, _ := tokens.Issue(enrolltoken.DefaultPolicy(), "tenant_test", "", "", "adm_alice", "", now.Add(72*time.Hour), now)
	tokens.Revoke(killedTok.ID, "adm_alice", now)
	_, lapsed, _ := tokens.Issue(enrolltoken.DefaultPolicy(), "tenant_test", "", "", "adm_alice", "", now.Add(time.Millisecond), now)
	time.Sleep(5 * time.Millisecond)

	var answers []string
	for _, secret := range []string{spent, killed, lapsed, "never-issued-at-all"} {
		code, resp := enrolPost(t, mux, "probe", secret)
		if code != http.StatusForbidden {
			t.Fatalf("expected refusal, got %d", code)
		}
		answers = append(answers, resp.Error)
	}
	for i, got := range answers {
		if got != answers[0] {
			t.Fatalf("refusal %d differs (%q vs %q) — a caller can tell which tokens exist", i, got, answers[0])
		}
	}
}

// A token an admin disabled the DEVICE for must not be burned on an enrolment that is refused anyway: the admin
// would be re-issuing for a machine that was never going to be admitted.
func TestARefusedEnrolmentDoesNotSpendTheToken(t *testing.T) {
	mux, tokens, ledger := newTokenEnrolTestMux(t)
	secret := mintToken(t, tokens, 72*time.Hour)

	if code, _ := enrolPost(t, mux, "laptop-01", secret); code != http.StatusOK {
		t.Fatalf("setup enrolment failed")
	}
	ledger.SetEnabled("laptop-01", false, time.Now().UTC().Format(time.RFC3339))

	second := mintToken(t, tokens, 72*time.Hour)
	if code, _ := enrolPost(t, mux, "laptop-01", second); code != http.StatusForbidden {
		t.Fatalf("a disabled identity must be refused, got %d", code)
	}
	// The refusal was about the DEVICE, so the token is still good for the machine it was meant for.
	if code, resp := enrolPost(t, mux, "laptop-03", second); code != http.StatusOK || resp.CertPEM == "" {
		t.Fatalf("the token must survive a refusal it did not cause: code=%d err=%q", code, resp.Error)
	}
}

// The group an admin put on the token is what the device lands in — the device does not get to assert its own.
func TestTheTokenCarriesTheGroupTheAdminChose(t *testing.T) {
	mux, tokens, ledger := newTokenEnrolTestMux(t)
	now := time.Now().UTC()
	_, secret, err := tokens.Issue(enrolltoken.DefaultPolicy(), "tenant_test", "finance-laptops", "", "adm_alice", "", now.Add(72*time.Hour), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if code, resp := enrolPost(t, mux, "laptop-fin", secret); code != http.StatusOK {
		t.Fatalf("enrol: code=%d err=%q", code, resp.Error)
	} else if resp.Group != "finance-laptops" {
		t.Fatalf("the CP must assign the token's group, got %q", resp.Group)
	}
	if g, _ := ledger.GroupFor("laptop-fin"); g != "finance-laptops" {
		t.Fatalf("the ledger must record it too, got %q", g)
	}
}

// With no shared token configured and no store hit, nothing enrols. This is the deployment the lab now runs.
func TestNoCredentialEnrolsNothing(t *testing.T) {
	mux, _, _ := newTokenEnrolTestMux(t)
	for _, secret := range []string{"", "guess", "dsse-lab-enroll-token"} {
		if code, resp := enrolPost(t, mux, "laptop-x", secret); code != http.StatusForbidden || resp.CertPEM != "" {
			t.Fatalf("secret %q must not enrol: code=%d", secret, code)
		}
	}
}
