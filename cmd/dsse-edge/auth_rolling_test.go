package main

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/grantstore"
	old "github.com/lantern-networks/dsse-core/grantstore/testdata/releasedv031"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthDrainRejectsNewCeremoniesButKeepsIssuedGrant(t *testing.T) {
	b, g := ceremonyFixture(t)
	drain := &atomic.Bool{}
	b.draining = drain
	g.draining = drain
	_, e := b.grants.Mint(authTestBindGrant(t, g, grantstore.Grant{GrantID: "g", TenantID: "tenant", DeviceID: "device", UserID: "user", IdPID: "corp", Scope: "app:22"}), time.Hour, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	link := g.stepUpURLWithRequirements("app:22", "device", "tenant", federatedRequirements{OSPrincipal: testAuthPrincipal, OSSession: testAuthSession})
	if link == "" {
		t.Fatal("no start link before drain")
	}
	drain.Store(true)
	if !g.hasLiveGrantWithRequirements("tenant", "device", federatedRequirements{Scope: "app:22", OSPrincipal: testAuthPrincipal, OSSession: testAuthSession}) {
		t.Fatal("drain revoked issued authorization")
	}
	if g.stepUpURLWithRequirements("app:22", "other", "tenant", federatedRequirements{OSPrincipal: testAuthPrincipal, OSSession: testAuthSession}) != "" {
		t.Fatal("new ceremony on draining node")
	}
	w := httptest.NewRecorder()
	b.startForTest(w, httptest.NewRequest("GET", link, nil))
	if w.Code != 503 || len(b.pending) != 0 {
		t.Fatal("draining portal admitted new ceremony")
	}
}
func TestRollingBundleHidesSingleRequestFromReleasedDecoder(t *testing.T) {
	s := grantstore.NewStore()
	now := time.Now().UTC().Truncate(time.Second)
	normal := grantstore.Grant{GrantID: "normal", TenantID: "t"}
	if _, e := s.Mint(normal, time.Hour, now); e != nil {
		t.Fatal(e)
	}
	g := grantstore.Grant{GrantID: "single", TenantID: "t", DeviceID: "device", UserID: "user", IdPID: "idp", Issuer: "https://idp.example", ProviderConfigSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Scope: "app:22", AuthenticationRequestID: "req", ReauthenticationStartedAt: now.Format(time.RFC3339), AuthTime: now.Format(time.RFC3339)}
	if _, e := s.Mint(g, time.Minute, now); e != nil {
		t.Fatal(e)
	}
	wire, e := json.Marshal(grantBundleSection(s))
	if e != nil {
		t.Fatal(e)
	}
	var legacy struct {
		Grants   []old.Grant `json:"grants"`
		Complete bool        `json:"complete"`
	}
	if e = json.Unmarshal(wire, &legacy); e != nil {
		t.Fatal(e)
	}
	if !legacy.Complete || len(legacy.Grants) != 1 || legacy.Grants[0].GrantID != "normal" {
		t.Fatal("modern grant leaked into legacy bundle")
	}
	var newer grantBundle
	if e = json.Unmarshal(wire, &newer); e != nil {
		t.Fatal(e)
	}
	peer := grantstore.NewStore()
	if _, _, e = applyGrantBundleSectionChecked(peer, &newer, now); e != nil {
		t.Fatal(e)
	}
	if got, ok := peer.Get("single"); !ok || got.AuthenticationRequestID != "req" {
		t.Fatal("modern peer lost evidence")
	}
}

func TestProtectedGrantReporterRequiresVersionedEndpoint(t *testing.T) {
	store := grantstore.NewStore()
	now := time.Now().UTC().Truncate(time.Second)
	g := grantstore.Grant{GrantID: "future", TenantID: "t", RequiredFeatures: []string{"future-v2"}}
	if _, e := store.Mint(g, time.Minute, now); e != nil {
		t.Fatal(e)
	}
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.URL.Path != "/grant-report-v2" {
			t.Error("protected report used legacy route")
		}
		var body struct {
			Grants    []old.Grant        `json:"grants"`
			Protected []grantstore.Grant `json:"protected_grants"`
		}
		if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
			t.Error(e)
		}
		if len(body.Grants) != 0 || len(body.Protected) != 1 {
			t.Error("wrong transport partition")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	reporter := &grantCPReporter{url: server.URL + "/grant-report", client: server.Client(), grants: func() *grantstore.Store { return store }}
	reporter.report(context.Background())
	if !called {
		t.Fatal("report not sent")
	}
}
