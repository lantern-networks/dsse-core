package main

import "testing"

func TestPKIPathsDoNotShareCertificatesAcrossCaseDistinctTenants(t *testing.T) {
	inv := []pkiCertificateItem{{
		ID: "interception_root:acme_upper", Role: "interception_root", TenantID: "Acme",
		Subject: "CN=Upper tenant interception root",
	}}
	paths := []pkiPath{{
		ID: "interception", ServerCertID: inv[0].ID,
		ServerCertSubject: inv[0].Subject, ServerCertTenantID: "Acme",
		ClientAuthVerifiedBy: "CN=Upper tenant device CA", ClientAuthTenantID: "Acme",
	}}
	got := pkiPathsForTenant(paths, "acme", inv)
	if len(got) != 1 || got[0].ServerCertID != "" || got[0].ServerCertSubject != "" || got[0].ClientAuthVerifiedBy != "" {
		t.Fatalf("case-distinct tenant saw another tenant's PKI material: %+v", got)
	}
	owner := pkiPathsForTenant(paths, "Acme", inv)
	if len(owner) != 1 || owner[0].ServerCertID != inv[0].ID {
		t.Fatalf("certificate owner lost its own material: %+v", owner)
	}
}
