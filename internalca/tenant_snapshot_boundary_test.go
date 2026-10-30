package internalca

import (
	"reflect"
	"testing"
	"time"
)

func TestTenantReplacementRejectsAnotherOwnersAuthorityAtomically(t *testing.T) {
	now := time.Now()
	s, err := NewStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	own := Authority{ID: "own", TenantID: "tenant-a", CertificatePEM: caPEM(t, "Own", now.Add(time.Hour), true)}
	if _, err = s.Upsert(own, now); err != nil {
		t.Fatal(err)
	}
	before := s.ListAll(now)
	generation := s.ConfigGeneration()
	foreign := Authority{ID: "foreign", TenantID: "tenant-b", CertificatePEM: caPEM(t, "Foreign", now.Add(time.Hour), true)}
	if err = s.ReplaceTenant("tenant-a", []Authority{own, foreign}); err == nil {
		t.Error("another tenant's CA was relabelled and trusted")
	}
	if !reflect.DeepEqual(before, s.ListAll(now)) || generation != s.ConfigGeneration() {
		t.Error("rejected snapshot changed live trust")
	}
	if err = s.ReplaceTenant("tenant-a", []Authority{own}); err != nil {
		t.Fatal(err)
	}
	if err = s.ReplaceTenant("tenant-a", nil); err != nil {
		t.Fatal(err)
	}
	if len(s.AnchorsPEM("tenant-a", now)) != 0 {
		t.Fatal("explicit empty list must remove old tenant trust")
	}
}
