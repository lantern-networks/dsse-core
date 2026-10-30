package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/authrollout"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/grantstore"
	old "github.com/lantern-networks/dsse-core/grantstore/testdata/releasedv031"
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestAuthRollingReleasedCopiesThroughBundleAndReport(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := grantstore.NewStore()
	g, err := store.Mint(grantstore.Grant{GrantID: "new", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Issuer: "https://idp.example", ProviderConfigSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AuthTime: now.Format(time.RFC3339)}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	// Decode and re-encode with the frozen release's actual JSON contract.
	b, _ := json.Marshal(g)
	var released old.Grant
	if err = json.Unmarshal(b, &released); err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(released)
	var forwarded grantstore.Grant
	if err = json.Unmarshal(b, &forwarded); err != nil {
		t.Fatal(err)
	}
	if _, _, err = applyGrantBundleSectionChecked(store, &grantBundle{Grants: []grantstore.Grant{forwarded}, Complete: true}, now); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerGrantReportRoute(mux, store, nil, "", true) // Transport authorization is covered separately.
	send := func() {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"grants": []old.Grant{released}})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("POST", "/grant-report", bytes.NewReader(b)))
		if w.Code != http.StatusOK {
			t.Fatalf("report status %d", w.Code)
		}
	}
	send()
	got, ok := store.Get(g.GrantID)
	if !ok || !store.Valid(g.GrantID, now) || got.AuthTime != g.AuthTime || got.Issuer != g.Issuer {
		t.Fatal("legacy transport erased authenticated evidence")
	}
	released.Revoked = true
	send()
	if store.Valid(g.GrantID, now) {
		t.Fatal("legacy report failed to revoke")
	}
}

func reviewRolloutCache(t *testing.T) *authRolloutRuntime {
	t.Helper()
	r := &authRolloutRuntime{cache: authrollout.NewCache(authrollout.NewStore(blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "cache.json")}))}
	prior := theAuthRollout.Swap(r)
	t.Cleanup(func() { theAuthRollout.Store(prior) })
	return r
}

func TestAuthRolloutFailureDoesNotBlockPolicyRevocationOrIdP(t *testing.T) {
	r := reviewRolloutCache(t)
	authority, m := rolloutFixture(t)
	if err := authority.authority.Configure(context.Background(), 0, m); err != nil {
		t.Fatal(err)
	}
	good, _ := authority.authority.Distribute(time.Now())
	if err := r.adopt(good, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	bad := *good
	bad.State.Revision = 0 // Invalid auxiliary state must not block security changes.
	store := grantstore.NewStore()
	g, err := store.Mint(grantstore.Grant{GrantID: "revoke", TenantID: "tenant"}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	g.Revoked = true
	oldStore := theGrantStore.Swap(store)
	t.Cleanup(func() { theGrantStore.Store(oldStore) })
	registry := idpregistry.NewStore()
	oldRegistry := theIdPRegistry.Swap(registry)
	t.Cleanup(func() { theIdPRegistry.Store(oldRegistry) })
	_, provider := rollingProcessProvider(t)
	ps := policy.NewStore(nil)
	payload := configBundlePayload{Generation: 42, AuthRollout: &bad, signatureVerified: true, Policies: []model.Policy{{ID: "new-policy", TenantID: "tenant", Conditions: map[string]any{"host": "example.com"}, Action: model.PolicyAction{Decision: "deny"}}}, Grants: &grantBundle{Grants: []grantstore.Grant{g}, Complete: true}, IdPConnections: &idpConnectionBundle{Connections: []idpregistry.Connection{provider}, Complete: true}}
	if _, err = (configBundleSource{tenantID: "tenant"}).apply(payload, configApplyTargets{policyStore: ps}); err != nil {
		t.Fatal(err)
	}
	if len(ps.Snapshot("tenant")) != 1 || store.Valid(g.GrantID, time.Now()) || len(registry.ListAll()) != 1 {
		t.Fatal("auxiliary failure blocked authoritative sections")
	}
	cached, _ := r.cache.Read()
	if cached.State.Revision != good.State.Revision || r.statusSnapshot()["status"] != "rejected" {
		t.Fatal("prior rollout state or rejection status lost")
	}
}

func TestAuthRolloutSignedPollUpdatesWithoutPolicyReapply(t *testing.T) {
	r := reviewRolloutCache(t)
	authority, m := rolloutFixture(t)
	if err := authority.authority.Configure(context.Background(), 0, m); err != nil {
		t.Fatal(err)
	}
	initial, _ := authority.authority.Distribute(time.Now())
	completeRollout(t, authority, m)
	completed, _ := authority.authority.Distribute(time.Now())
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(d *authrollout.Distribution) []byte {
		e, err := signer.Sign(configBundlePayload{Generation: 7, Epoch: "cp", Policies: []model.Policy{{ID: "p", TenantID: "tenant", Conditions: map[string]any{"host": "example.com"}, Action: model.PolicyAction{Decision: "deny"}}}, AuthRollout: d}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first, second := encode(initial), encode(completed)
	var next atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if next.Load() {
			w.Write(second)
		} else {
			w.Write(first)
		}
	}))
	defer server.Close()
	ps := policy.NewStore(nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	src := configBundleSource{url: server.URL, client: server.Client(), interval: 10 * time.Millisecond, tenantID: "tenant", verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	go func() { defer close(done); src.run(ctx, configApplyTargets{policyStore: ps}) }()
	defer func() { cancel(); <-done }()
	wait := func(f func() bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for !f() {
			if time.Now().After(deadline) {
				t.Fatal("bundle did not converge")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	wait(func() bool { return len(ps.Snapshot("tenant")) == 1 })
	generation := ps.ConfigGeneration()
	next.Store(true)
	wait(func() bool { d, e := r.cache.Read(); return e == nil && d.State.Complete })
	if ps.ConfigGeneration() != generation {
		t.Fatal("runtime report reapplied policies")
	}
}
