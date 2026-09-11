package enroll

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// enroll_server_record_refusal_test.go — a record that refuses must stop the certificate.
//
// ★ RecordFunc RETURNED NOTHING (2026-08-12, nineteenth review), so the ledger's own refusals — a disabled
// identity, one already belonging to another tenant — could be logged and no more: the endpoint had already
// decided to answer 200 and hand over a usable identity. Every guard placed inside Record was decoration
// until the signature could say no.

func TestARecordThatRefusesYieldsNoCertificate(t *testing.T) {
	signer, caPin := newDeviceCASigner(t)

	iss := Issuer{
		Signer: signer,
		Assign: func(req Request) (string, string, string, bool) { return "acme", "", "", true },
		Record: func(deviceID, tenant, group string) error {
			return errors.New("identity belongs to another tenant")
		},
	}
	srv := httptest.NewServer(iss.Handler())
	defer srv.Close()

	res, err := Run(context.Background(), srv.URL, "win-dev-1", "acme", caPin,
		Eligibility{Mode: "token", Token: "good"}, http.DefaultClient)

	if err == nil {
		t.Fatalf("a refused record still produced an enrolment: cert=%d bytes, tenant=%q",
			len(res.CertPEM), res.Tenant)
	}
	if len(res.CertPEM) != 0 {
		t.Fatalf("a certificate was handed over despite the refusal (%d bytes)", len(res.CertPEM))
	}
	if !strings.Contains(strings.ToLower(err.Error()), "eligible") && !strings.Contains(err.Error(), "403") {
		t.Fatalf("the refusal did not reach the caller as one: %v", err)
	}
}
