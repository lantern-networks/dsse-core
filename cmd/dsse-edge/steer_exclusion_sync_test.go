package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	steerexclusion "github.com/lantern-networks/dsse-core/steerexclusion"
)

func TestSteerExclusionSourceFetchAndReplace(t *testing.T) {
	store := steerexclusion.NewStore()
	// Seed a STALE cached policy for the tenant — the sync must replace it with the CP's authoritative set.
	if _, err := store.Upsert(steerexclusion.Policy{
		TenantID: "t1", ScopeType: "device", ScopeID: "dev-1", ExcludedAppSigningIDs: []string{"stale.app"},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no auth", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"steer_exclusions": []map[string]any{{
			"id": "sx_cp_1", "tenant_id": "t1", "scope_type": "device", "scope_id": "dev-1",
			"excluded_app_signing_ids": []string{"corpvpn.exe"}, "status": "active",
		}}})
	}))
	defer srv.Close()

	src := steerExclusionSource{url: srv.URL, token: "tok", tenantID: "t1", client: srv.Client()}
	n, err := src.fetchAndReplace(context.Background(), store)
	if err != nil || n != 1 {
		t.Fatalf("fetchAndReplace = (%d,%v), want (1,nil)", n, err)
	}
	// The stale policy is gone; the CP set resolves for the device.
	if got := store.ResolveForDevice("t1", "dev-1", ""); !reflect.DeepEqual(got, []string{"corpvpn.exe"}) {
		t.Fatalf("resolved = %v, want [corpvpn.exe] (stale replaced by CP set)", got)
	}
}

func TestSteerExclusionSourceFailSafeKeepsCache(t *testing.T) {
	store := steerexclusion.NewStore()
	store.Upsert(steerexclusion.Policy{
		TenantID: "t1", ScopeType: "device", ScopeID: "dev-1", ExcludedAppSigningIDs: []string{"keep.app"},
	}, time.Now())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "cp down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	src := steerExclusionSource{url: srv.URL, token: "tok", tenantID: "t1", client: srv.Client()}
	if _, err := src.fetchAndReplace(context.Background(), store); err == nil {
		t.Fatal("a CP error must return an error")
	}
	// Fail-safe: the cache is untouched — the Edge keeps enforcing the last good set.
	if got := store.ResolveForDevice("t1", "dev-1", ""); !reflect.DeepEqual(got, []string{"keep.app"}) {
		t.Fatalf("resolved = %v, want [keep.app] (cache kept on CP failure)", got)
	}
}

func TestReplaceTenantIsolatesTenants(t *testing.T) {
	store := steerexclusion.NewStore()
	store.Upsert(steerexclusion.Policy{TenantID: "t1", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"a"}}, time.Now())
	store.Upsert(steerexclusion.Policy{TenantID: "t2", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"b"}}, time.Now())
	// Replacing t1 must not disturb t2.
	store.ReplaceTenant("t1", []steerexclusion.Policy{{ID: "sx_new", TenantID: "t1", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"c"}, Status: "active"}})
	if got := store.ResolveForDevice("t1", "dev", ""); !reflect.DeepEqual(got, []string{"c"}) {
		t.Fatalf("t1 resolved = %v, want [c]", got)
	}
	if got := store.ResolveForDevice("t2", "dev", ""); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("t2 resolved = %v, want [b] (unaffected by t1 replace)", got)
	}
}
