package main

import (
	"testing"
	"time"
)

func TestInterceptionAuthorityKeepsCaseDistinctTenantIdentities(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	rootA, keyA := interceptionTestCA(t, "Acme Root", nil, nil, now)
	issuerA, issuerKeyA := interceptionTestCA(t, "Acme Issuer", rootA, keyA, now)
	rootB, keyB := interceptionTestCA(t, "acme Root", nil, nil, now)
	issuerB, issuerKeyB := interceptionTestCA(t, "acme Issuer", rootB, keyB, now)
	a := newTenantInterceptionAuthority(nil, func([]byte) error { return nil }, func() time.Time { return now })
	if _, err := a.Import("Acme", certPEMForTest(rootA), certPEMForTest(issuerA), ecKeyPEMForTest(t, issuerKeyA)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Import("acme", certPEMForTest(rootB), certPEMForTest(issuerB), ecKeyPEMForTest(t, issuerKeyB)); err != nil {
		t.Fatal(err)
	}
	if got := a.Organizations(); len(got) != 2 || got[0] != "Acme" || got[1] != "acme" {
		t.Fatalf("case-distinct tenant authorities merged: %v", got)
	}
	for _, tenant := range []string{"Acme", "acme"} {
		material, err := a.IssueFor(tenant, "edge-1", time.Hour)
		if err != nil || material.TenantID != tenant {
			t.Fatalf("issue for %q: tenant=%q err=%v", tenant, material.TenantID, err)
		}
	}
	if removed, err := a.RemoveTenantChecked("Acme"); err != nil || removed != 1 || a.Has("Acme") || !a.Has("acme") {
		t.Fatalf("purge Acme affected acme: removed=%d err=%v", removed, err)
	}
}
