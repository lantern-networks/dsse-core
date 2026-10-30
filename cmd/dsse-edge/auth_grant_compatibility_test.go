package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/grantstore"
)

func TestMixedUpgradeKeepsLocalIssuanceWithOldCP(t *testing.T) {
	var calls atomic.Int32
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(404) }))
	defer cp.Close()
	r, m := rolloutFixture(t)
	if err := r.authority.Configure(context.Background(), 0, m); err != nil {
		t.Fatal(err)
	}
	b := &clientlessBroker{rollout: r, grants: grantstore.NewStore(), authorityRequired: true, authority: &grantCPReporter{url: cp.URL + "/grant-report", client: cp.Client()}}
	if _, err := b.reauthenticationBoundary(context.Background(), grantstore.Grant{TenantID: "tenant", Scope: "app:22"}); err != nil {
		t.Fatal("mixed upgrade required a new CP route", err)
	}
	now := time.Now().UTC()
	if _, err := b.mintGrant(context.Background(), grantstore.Grant{GrantID: "local-mixed", TenantID: "tenant", UserID: "user", Scope: "app:22"}, time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || len(b.grants.ListAll()) != 1 {
		t.Fatal("pre-activation issued remotely or lost grant")
	}
	features := []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature, authrollout.DeviceUserFeature, authrollout.RevocationReauthenticationFeature}
	for _, member := range m.Members {
		if err := r.authority.Record(context.Background(), member.CertificateSHA256, authrollout.Report{NodeID: member.ID, Generation: m.Generation, Version: "new", Features: features}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.authority.Activate(context.Background(), m.Generation, features, now); err != nil {
		t.Fatal(err)
	}
	if _, err := b.reauthenticationBoundary(context.Background(), grantstore.Grant{TenantID: "tenant", Scope: "app:22"}); err == nil {
		t.Fatal("activated fleet fell back to local authority")
	}
	if _, err := b.mintGrant(context.Background(), grantstore.Grant{GrantID: "activated", TenantID: "tenant", UserID: "user", Scope: "app:22"}, time.Minute, now); err == nil {
		t.Fatal("activated fleet issued unconfirmed grant")
	}
	if calls.Load() != 2 || len(b.grants.ListAll()) != 1 {
		t.Fatal("activated authority error left an allow")
	}
}

func TestMixedUpgradeAdministrativeRevocationRemainsAvailable(t *testing.T) {
	r, m := rolloutFixture(t)
	if err := r.authority.Configure(context.Background(), 0, m); err != nil {
		t.Fatal(err)
	}
	store := grantstore.NewStore()
	if _, err := store.Mint(grantstore.Grant{GrantID: "old", TenantID: "tenant"}, time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerGrantsAdmin(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h(w, requestWithAdminIdentity(r, adminIdentity{TenantID: "tenant"}))
		}
	}, store, testEvaluator(), nil, nil, r, "")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/admin/grants/old/revoke", nil))
	var result struct {
		Status string `json:"status"`
		Fresh  *bool  `json:"fresh_identity_required"`
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || w.Code != 200 || result.Status != "revoked" || result.Fresh == nil || *result.Fresh {
		t.Fatalf("mixed revocation unavailable or overclaimed: %d %s", w.Code, w.Body)
	}
	g, ok := store.Get("old")
	if !ok || !g.Revoked || g.ReauthenticateAfter != "" {
		t.Fatal("mixed revocation did not retain legacy semantics")
	}
}
