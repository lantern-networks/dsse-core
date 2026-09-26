package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func delegatedFixture(tenant, id string) model.DelegatedAccessGrant {
	return model.DelegatedAccessGrant{ID: id, TenantID: tenant, SubjectUserID: "person", ActorNHIID: "agent", Status: "active", Scopes: []string{"read"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
}
func delegatedHandler(t *testing.T, s *delegatedgrant.Store) (http.Handler, *logs.Writer) {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { writer.Close() })
	mux := http.NewServeMux()
	registerNHIPillarRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, testEvaluator(), writer, nil, nil, nil, s, nil, "")
	return mux, writer
}
func delegatedWrite(t *testing.T, h http.Handler, g model.DelegatedAccessGrant, want int) {
	t.Helper()
	b, _ := json.Marshal(adminDelegatedAccessGrantFromModel(g))
	w := libraryRequest(h, "POST", "/admin/delegated-grants", string(b), g.TenantID)
	if w.Code != want {
		t.Fatalf("grant write status=%d want%d", w.Code, want)
	}
}

type delegatedPGGate struct {
	postgresBlobPersister
	fail bool
}

func (p *delegatedPGGate) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	return p.postgresBlobPersister.UpdateContext(ctx, func(b []byte) ([]byte, error) {
		next, err := f(b)
		if err != nil {
			return nil, err
		}
		if p.fail {
			return nil, errors.New("private storage detail")
		}
		return next, nil
	})
}
func TestPostgresDelegatedGrantPeerLifecycle(t *testing.T) {
	db := initialBlobDB(t)
	p := initialBlob(t, db, "delegated_peer")
	gate := &delegatedPGGate{postgresBlobPersister: p}
	a, b := delegatedgrant.NewStore(0), delegatedgrant.NewStore(0)
	if err := a.SetPersister(gate); err != nil {
		t.Fatal(err)
	}
	if err := b.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	ha, writer := delegatedHandler(t, a)
	hb, _ := delegatedHandler(t, b)
	g := delegatedFixture("own", "same")
	delegatedWrite(t, ha, g, 200)
	delegatedWrite(t, hb, delegatedFixture("foreign", "same"), 200)
	delegatedWrite(t, hb, delegatedFixture("own", "peer"), 200)
	g.Scopes = []string{"read", "write"}
	delegatedWrite(t, ha, g, 200)
	w := libraryRequest(hb, "GET", "/admin/delegated-grants/same", "", "own")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"write"`) {
		t.Fatal("peer edit missing")
	}
	if got, ok := b.GetForTenant("foreign", "same"); !ok || len(got.Scopes) != 1 {
		t.Fatal("other organization overwritten")
	}
	gate.fail = true
	w = libraryRequest(ha, "POST", "/admin/delegated-grants/same/revoke", `{"revocation_reason_code":"requested"}`, "own")
	if w.Code != 500 || !strings.Contains(w.Body.String(), `"status":"partial"`) || strings.Contains(w.Body.String(), "private storage detail") {
		t.Fatal("unconfirmed revoke not reported accurately")
	}
	if got, _ := a.GetForTenant("own", "same"); got.Status != "revoked" {
		t.Fatal("failed revoke lost local denial")
	}
	if got, _ := b.GetForTenant("own", "same"); got.Status != "active" {
		t.Fatal("fixture unexpectedly committed failed revoke")
	}
	gate.fail = false
	w = libraryRequest(ha, "POST", "/admin/delegated-grants/same/revoke", `{}`, "own")
	if w.Code != 200 {
		t.Fatal("retry failed", w.Code)
	}
	if got, _ := b.GetForTenant("own", "same"); got.Status != "revoked" {
		t.Fatal("confirmed revoke missing on peer")
	}
	delegatedWrite(t, hb, g, 409)
	if got, ok := b.GetForTenant("own", "peer"); !ok || got.Status != "active" {
		t.Fatal("peer grant erased")
	}
	var partial, success int
	for _, row := range readConnectorManagementAudits(t, writer) {
		if row.EventType != "admin_delegated_access_grant_revoked" {
			continue
		}
		if stringPtrValue(row.ActorUserID) != "admin" || row.TenantID != "own" {
			t.Fatal("audit actor or target missing")
		}
		if stringPtrValue(row.Result) == "partial" {
			partial++
		}
		if stringPtrValue(row.Result) == "revoked" {
			success++
		}
	}
	if partial != 1 || success != 1 {
		t.Fatal("revocation audits misrepresent save outcome", partial, success)
	}
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	if w := libraryRequest(hb, "GET", "/admin/delegated-grants", "", "own"); w.Code != 500 {
		t.Fatal("missing shared authority reported empty success")
	}
}
func TestDelegatedGrantReceiverSaveRetryAndRevoke(t *testing.T) {
	s := delegatedgrant.NewStore(0)
	p := &allowlistSaveFixture{}
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	g := delegatedFixture("own", "grant")
	payload := configBundlePayload{DelegatedGrants: &delegatedGrantBundle{Grants: []model.DelegatedAccessGrant{g}}}
	src := configBundleSource{}
	targets := configApplyTargets{delegatedGrants: s}
	p.err = errors.New("unavailable")
	if _, err := src.apply(payload, targets); err == nil {
		t.Fatal("receiver acknowledged failed creation")
	}
	if s.Count() != 0 {
		t.Fatal("failed creation became active")
	}
	p.err = nil
	if _, err := src.apply(payload, targets); err != nil {
		t.Fatal(err)
	}
	payload.DelegatedGrants.Grants[0].Status = "revoked"
	p.err = errors.New("unavailable")
	if _, err := src.apply(payload, targets); err == nil {
		t.Fatal("receiver acknowledged failed revoke save")
	}
	if g, ok := s.GetForTenant("own", "grant"); !ok || delegatedgrant.IsActive(g, time.Now()) {
		t.Fatal("received revoke allowed access during failed save")
	}
	p.err = nil
	if _, err := src.apply(payload, targets); err != nil {
		t.Fatal(err)
	}
	fresh := delegatedgrant.NewStore(0)
	if err := fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if g, ok := fresh.GetForTenant("own", "grant"); !ok || delegatedgrant.IsActive(g, time.Now()) {
		t.Fatal("revoked grant active after reload")
	}
	payload.DelegatedGrants.Grants[0].Status = "active"
	if _, err := src.apply(payload, targets); err == nil {
		t.Fatal("stale active snapshot revived revoked grant")
	}
	if _, err := src.apply(configBundlePayload{DelegatedGrants: &delegatedGrantBundle{}}, targets); err != nil {
		t.Fatal(err)
	}
	if g, ok := s.GetForTenant("own", "grant"); !ok || g.Status != "revoked" {
		t.Fatal("legacy empty bundle removed revocation")
	}
}
func TestDelegatedGrantReceiverStoreSelection(t *testing.T) {
	db := &sql.DB{}
	for _, value := range []string{"", filepath.Join(t.TempDir(), "grants.json")} {
		p, err := delegatedGrantPersisterForRole(value, db, "https://cp.example.invalid")
		if err != nil {
			t.Fatal(err)
		}
		s := delegatedgrant.NewStore(0)
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Upsert(delegatedFixture("own", "grant")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := delegatedGrantPersisterForRole("postgres", db, "https://cp.example.invalid"); err == nil {
		t.Fatal("receiver can overwrite CP authority")
	}
}

func TestPostgresDelegatedGrantBundleRefresh(t *testing.T) {
	db := initialBlobDB(t)
	p := initialBlob(t, db, "delegated_bundle")
	a, b := delegatedgrant.NewStore(0), delegatedgrant.NewStore(0)
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	prev := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(prev) })
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: newAdminAuthStore(), DelegatedGrants: a})
	for _, s := range []*delegatedgrant.Store{a, b} {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	fetch := func(want int) configBundlePayload {
		t.Helper()
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("GET", "/admin/config-bundle", nil))
		if r.Code != want {
			t.Fatal("bundle response", r.Code, want)
		}
		var bundle configBundlePayload
		if want == 200 {
			if err := json.Unmarshal(r.Body.Bytes(), &bundle); err != nil {
				t.Fatal(err)
			}
		}
		return bundle
	}
	before := fetch(200)
	if _, err := b.Upsert(delegatedFixture("own", "peer")); err != nil {
		t.Fatal(err)
	}
	active := fetch(200)
	if active.DelegatedGrants == nil || len(active.DelegatedGrants.Grants) != 1 || active.Generation <= before.Generation {
		t.Fatal("peer creation not refreshed before bundle generation")
	}
	if _, err := b.RevokeForTenant("own", "peer", "requested", time.Now()); err != nil {
		t.Fatal(err)
	}
	revoked := fetch(200)
	if revoked.DelegatedGrants.Grants[0].Status != "revoked" || revoked.Generation <= active.Generation {
		t.Fatal("peer revocation not refreshed before bundle generation")
	}
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	fetch(503)
}
