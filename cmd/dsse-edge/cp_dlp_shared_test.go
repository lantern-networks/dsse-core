package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresDLPSharedPeerAndAcceptedTerm(t *testing.T) {
	a, b := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keys := map[string]string{"allowlist": "dlp_allowlist", "classifiers": "dlp_classifiers", "fingerprints": "dlp_fingerprints", "policies": "dlp_policy_objects"}
	// Same isolated database contract as the other CP acceptance suites.
	for _, key := range append([]string{"entitlements"}, keys["allowlist"], keys["classifiers"], keys["fingerprints"], keys["policies"]) {
		p := postgresBlobPersister{db: db, key: key}
		saved, e := p.Load()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key); e != nil {
			t.Fatal(e)
		}
		defer func() {
			if saved != nil {
				p.Save(saved)
			} else {
				db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
			}
		}()
	}
	for name, factory := range dlpPeerFactories() {
		t.Run("peer_"+name, func(t *testing.T) {
			p := postgresBlobPersister{db: db, key: keys[name]}
			x, y := factory(), factory()
			if e := x.attach(p); e != nil {
				t.Fatal(e)
			}
			if e := y.attach(p); e != nil {
				t.Fatal(e)
			}
			if e := x.write("one"); e != nil {
				t.Fatal(e)
			}
			if e := y.write("foreign"); e != nil {
				t.Fatal(e)
			}
			restored := factory()
			if e := restored.attach(p); e != nil {
				t.Fatal(e)
			}
			if !restored.present("one") || !restored.present("foreign") {
				t.Fatal("peer configuration lost on restore")
			}
		})
	}
	tenant := testEvaluator().PolicyBundle.TenantID
	if err := (postgresBlobPersister{db: db, key: "entitlements"}).Save([]byte(`{"features":{"` + tenant + `":{"dlp":true}}}`)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "dlp-admin", TenantID: tenant, Roles: []string{"admin", "super_admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "dlp-session", TenantID: tenant, AdminPrincipalID: "dlp-admin", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "dlp-csrf"}})
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	oldDB, oldE := cpStateBlobDB, cpLeaderElectorInstance
	cpStateBlobDB = db
	defer func() { cpStateBlobDB, cpLeaderElectorInstance = oldDB, oldE }()
	config := serverConfig{Evaluator: testEvaluator(), Writer: w, AdminAuth: auth, OperatorTenantID: tenant, EntitlementStorePath: "postgres", DLPAllowlistStorePath: "postgres", DLPClassifierStorePath: "postgres", DLPFingerprintStorePath: "postgres", DLPPolicyObjectStorePath: "postgres"}
	h := newServerWithConfig(config)
	cpLeaderElectorInstance = a
	a.tick()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "dlp-session"})
		r.Header.Set("X-CSRF-Token", "dlp-csrf")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr
	}
	cases := []struct{ name, body string }{
		{"allowlist", `{"values":["safe-current"]}`},
		{"classifiers", `{"classifiers":[{"name":"project_code","kind":"keyword","keywords":["CURRENT"]}]}`},
		{"fingerprints", `{"name":"dataset","values":["sample-current"]}`},
		{"policies", `{"id":"policy","name":"Current","identifiers":["email"],"on_match":"observe"}`},
	}
	for _, c := range cases {
		t.Run("request_term_"+c.name, func(t *testing.T) {
			p := postgresBlobPersister{db: db, key: keys[c.name]}
			before, e := p.Load()
			if e != nil {
				t.Fatal(e)
			}
			body := &pausedSeatBody{Reader: strings.NewReader(c.body), entered: make(chan struct{}), resume: make(chan struct{})}
			r := httptest.NewRequest("POST", "/admin/dlp-"+c.name, body)
			r.AddCookie(&http.Cookie{Name: "admin_session", Value: "dlp-session"})
			r.Header.Set("X-CSRF-Token", "dlp-csrf")
			rr := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); h.ServeHTTP(rr, r) }()
			select {
			case <-body.entered:
			case <-done:
				t.Fatalf("body unread %d %s", rr.Code, rr.Body)
			case <-time.After(5 * time.Second):
				t.Fatal("body timeout")
			}
			a.release()
			b.tick()
			if !b.IsLeader() {
				t.Fatal("peer not elected")
			}
			b.release()
			a.tick()
			if !a.IsLeader() {
				t.Fatal("reacquire failed")
			}
			close(body.resume)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("response timeout")
			}
			after, e := p.Load()
			if e != nil {
				t.Fatal(e)
			}
			if rr.Code != 500 || !bytes.Equal(before, after) {
				t.Fatalf("old term accepted: %d %s", rr.Code, rr.Body)
			}
			if fresh := request("POST", "/admin/dlp-"+c.name, c.body); fresh.Code != 200 {
				t.Fatalf("fresh write %d %s", fresh.Code, fresh.Body)
			}
			peer := dlpPeerFactories()[c.name]()
			if e := peer.attach(p); e != nil {
				t.Fatal(e)
			}
			if !peer.present("foreign") {
				t.Fatal("foreign state lost")
			}
			if e := peer.write(tenant); e != nil {
				t.Fatal(e)
			}
			if read := request("GET", "/admin/dlp-"+c.name, ""); read.Code != 200 || !strings.Contains(read.Body.String(), tenant) {
				// Fingerprints list only dataset name and count; other stores contain tenant-specific fixture values.
				if c.name != "fingerprints" || read.Code != 200 {
					t.Fatalf("checked read %d %s", read.Code, read.Body)
				}
			}
		})
	}
	// Deletions also retain the admission term and preserve unrelated tenants.
	policy := newDLPPolicyObjectStore()
	fp := newDLPFingerprintRuntimeStore("salt")
	if e := policy.SetPersister(postgresBlobPersister{db: db, key: keys["policies"]}); e != nil {
		t.Fatal(e)
	}
	if e := fp.SetPersister(postgresBlobPersister{db: db, key: keys["fingerprints"]}); e != nil {
		t.Fatal(e)
	}
	stale := captureCPWriteLease(context.Background())
	a.release()
	b.tick()
	b.release()
	a.tick()
	if _, e := policy.DeleteContext(stale, tenant, "policy"); e == nil {
		t.Fatal("old-term policy delete accepted")
	}
	if _, e := fp.RemoveDatasetContext(stale, tenant, "dataset"); e == nil {
		t.Fatal("old-term dataset delete accepted")
	}
	for _, path := range []string{"/admin/dlp-policies?id=policy", "/admin/dlp-fingerprints?name=dataset"} {
		if rr := request("DELETE", path, ""); rr.Code != 200 {
			t.Fatalf("delete %d %s", rr.Code, rr.Body)
		}
	}

	for _, name := range []string{"policies", "fingerprints"} {
		restored := dlpPeerFactories()[name]()
		if e := restored.attach(postgresBlobPersister{db: db, key: keys[name]}); e != nil {
			t.Fatal(e)
		}
		if restored.present(tenant) || !restored.present("foreign") {
			t.Fatal("delete restore differs")
		}
	}
	// The already-running publisher must refresh without an admin GET or restart.
	var previous configBundlePayload
	initialBundle := request("GET", "/admin/config-bundle", "")
	if initialBundle.Code != 200 {
		t.Fatal("initial bundle unavailable")
	}
	if e := json.Unmarshal(initialBundle.Body.Bytes(), &previous); e != nil {
		t.Fatal(e)
	}
	for name, factory := range dlpPeerFactories() {
		peer := factory()
		if e := peer.attach(postgresBlobPersister{db: db, key: keys[name]}); e != nil {
			t.Fatal(e)
		}
		if e := peer.write("bundle_peer"); e != nil {
			t.Fatal(e)
		}
	}
	rr := request("GET", "/admin/config-bundle", "")
	var next configBundlePayload
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &next) != nil {
		t.Fatalf("fresh bundle %d", rr.Code)
	}
	if next.DLP == nil || len(next.DLP.Policies["bundle_peer"]) != 1 || len(next.DLP.Classifiers["bundle_peer"]) != 1 || len(next.DLP.Datasets["bundle_peer"]) != 1 || len(next.DLP.Allowlists["bundle_peer"]) != 1 || next.Generation <= previous.Generation {
		t.Fatal("publisher returned stale library/generation")
	}
	// A fresh process loads the same acknowledged state; bundle reads refresh all libraries.
	h = newServerWithConfig(config)
	if rr := request("GET", "/admin/config-bundle", ""); rr.Code != 200 {
		t.Fatalf("bundle %d %s", rr.Code, rr.Body)
	}
	for _, c := range cases {
		p := postgresBlobPersister{db: db, key: keys[c.name]}
		saved, e := p.Load()
		if e != nil {
			t.Fatal(e)
		}
		if e = p.Save([]byte(`{}`)); e != nil {
			t.Fatal(e)
		}
		if rr := request("GET", "/admin/dlp-"+c.name, ""); rr.Code != 503 {
			t.Fatalf("corrupt %s read %d", c.name, rr.Code)
		}
		if rr := request("GET", "/admin/config-bundle", ""); rr.Code != 503 {
			t.Fatalf("corrupt %s published %d", c.name, rr.Code)
		}
		if e = p.Save(saved); e != nil {
			t.Fatal(e)
		}
	}
	outcomes := map[string]int{}
	for _, row := range readTransportAudits(t, w) {
		if row.EventType == "admin_config_change" && row.TargetID != nil && strings.HasPrefix(*row.TargetID, "/admin/dlp-") && row.Result != nil {
			outcomes[*row.Result]++
		}
	}
	if outcomes["error"] != 4 || outcomes["success"] != 6 {
		raw, _ := json.Marshal(outcomes)
		t.Fatalf("audit mismatch %s", raw)
	}
}
