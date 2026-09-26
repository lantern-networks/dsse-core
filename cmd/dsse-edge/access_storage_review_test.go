package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/vlan"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAccessStorageFailuresRemainRetryable(t *testing.T) {
	now := time.Now()
	g := grantstore.Grant{GrantID: "one", TenantID: "t", IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	store := grantstore.NewStore()
	p := &allowlistSaveFixture{}
	store.SetPersister(p)
	p.err = errors.New("storage unavailable")
	prev := theGrantStore.Load()
	theGrantStore.Store(store)
	t.Cleanup(func() { theGrantStore.Store(prev) })
	payload := configBundlePayload{Grants: &grantBundle{Complete: true, Grants: []grantstore.Grant{g}}}
	src := configBundleSource{}
	if _, e := src.apply(payload, configApplyTargets{}); e == nil {
		t.Fatal("grant save failure acknowledged")
	}
	mux := http.NewServeMux()
	registerGrantReportRoute(mux, store, nil, "", true)
	raw, _ := json.Marshal(map[string]any{"grants": []grantstore.Grant{g}})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/grant-report", bytes.NewReader(raw)))
	if w.Code != 503 {
		t.Fatalf("report status %d", w.Code)
	}
	p.err = nil
	if _, e := src.apply(payload, configApplyTargets{}); e != nil {
		t.Fatal(e)
	}
	if !store.Valid("one", now) {
		t.Fatal("retry did not save grant")
	}
}
func TestVLANStorageFailureNotAcknowledged(t *testing.T) {
	s := vlan.NewStore()
	p := &allowlistSaveFixture{}
	s.SetPersister(p)
	p.err = errors.New("storage unavailable")
	src := configBundleSource{}
	payload := configBundlePayload{VLAN: &vlanBoundaryBundle{Complete: true}}
	if _, e := src.apply(payload, configApplyTargets{vlan: s}); e == nil {
		t.Fatal("VLAN save failure acknowledged")
	}
	p.err = nil
	if _, e := src.apply(payload, configApplyTargets{vlan: s}); e != nil {
		t.Fatal(e)
	}
}
