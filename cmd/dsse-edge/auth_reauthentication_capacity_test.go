package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/grantstore"
)

func TestAdministrativeRevocationAtCapacityRemainsAvailableAndWarns(t *testing.T) {
	r, m := rolloutFixture(t)
	if err := r.authority.Configure(context.Background(), 0, m); err != nil {
		t.Fatal(err)
	}
	features := []string{authrollout.EvidenceFeature, authrollout.SingleRequestFeature, authrollout.DeviceUserFeature, authrollout.RevocationReauthenticationFeature}
	now := time.Now().UTC().Truncate(time.Second)
	for _, member := range m.Members {
		if err := r.authority.Record(context.Background(), member.CertificateSHA256, authrollout.Report{NodeID: member.ID, Generation: m.Generation, Version: "new", Features: features}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.authority.Activate(context.Background(), m.Generation, features, now); err != nil {
		t.Fatal(err)
	}
	store := grantstore.NewStore()
	rows := make([]grantstore.Grant, grantstore.MaxReauthenticationFencesPerTenant)
	for i := range rows {
		rows[i] = grantstore.Grant{GrantID: fmt.Sprint(i), TenantID: "tenant", UserID: "user", Scope: fmt.Sprint(i), Revoked: true, ReauthenticateAfter: now.Add(-time.Hour).Format(time.RFC3339), IssuedAt: now.Add(-2 * time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	}
	if _, _, err := store.MergeChecked(rows, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Mint(grantstore.Grant{GrantID: "target", TenantID: "tenant", Scope: "new"}, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerGrantsAdmin(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h(w, requestWithAdminIdentity(r, adminIdentity{TenantID: "tenant"}))
		}
	}, store, testEvaluator(), nil, nil, r, "")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/admin/grants/target/revoke", nil))
	var result struct {
		Status  string `json:"status"`
		Fresh   bool   `json:"fresh_identity_required"`
		Scope   string `json:"reauthentication_scope"`
		Warning string `json:"warning"`
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || w.Code != 200 || result.Status != "revoked" || !result.Fresh || result.Scope != "tenant" || result.Warning == "" {
		t.Fatalf("capacity revocation not accepted/warned: %d", w.Code)
	}
	if store.Valid("target", now) {
		t.Fatal("capacity left target active")
	}
}
