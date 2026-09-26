package main

import (
	"github.com/lantern-networks/dsse-core/internalca"
	"testing"
	"time"
)

func TestUnavailableInternalCANeverPublishesEmptyComplete(t *testing.T) {
	s := internalca.NewUnavailableStore("unavailable")
	section := internalCABundleSection(s)
	if section == nil || section.Complete {
		t.Fatal("unavailable authority published deletion")
	}
}
func TestInternalCAInvalidSnapshotRemainsRetryable(t *testing.T) {
	s, e := internalca.NewStore(nil)
	if e != nil {
		t.Fatal(e)
	}
	section := &internalCABundle{Complete: true, Authorities: []internalca.Authority{{ID: "a", TenantID: "t", CertificatePEM: anInternalAuthorityPEM(t, "Legacy")}}}
	section.Authorities[0].CertificatePEM = "Bag Attributes\n" + section.Authorities[0].CertificatePEM
	valid := section.Authorities[0].CertificatePEM
	section.Authorities[0].CertificatePEM = "invalid certificate"
	src := configBundleSource{}
	if _, e = src.apply(configBundlePayload{InternalCAs: section}, configApplyTargets{internalCAs: s}); e == nil {
		t.Fatal("invalid authority snapshot acknowledged")
	}
	if len(s.ListAll(time.Now())) != 0 {
		t.Fatal("rejected snapshot changed trust")
	}
	section.Authorities[0].CertificatePEM = valid
	if _, e = src.apply(configBundlePayload{InternalCAs: section}, configApplyTargets{internalCAs: s}); e != nil {
		t.Fatal(e)
	}
	if len(s.ListAll(time.Now())) != 1 {
		t.Fatal("retry did not restore authority")
	}
}
