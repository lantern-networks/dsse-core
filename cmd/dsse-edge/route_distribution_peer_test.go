package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/policy"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestPostgresRouteDistributionPeerHTTP(t *testing.T) {
	db := initialBlobDB(t)
	p := initialBlob(t, db, "route_distribution")
	a := newConnectorRouteGovernanceWithPersister("", true, p)
	b := newConnectorRouteGovernanceWithPersister("", true, p)
	prior := connectorRouteGov
	defer func() { connectorRouteGov = prior }()
	mux := http.NewServeMux()
	registerConnectorSiteAdminRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, serverConfig{}, testEvaluator(), nil, nil, nil, nil, nil, nil, nil, nil, nil, "", nil, func(context.Context, string, string) ([]string, []string, bool) { return nil, nil, true })
	call := func(g *connectorRouteGovernance, tenant, method, path, body string, want int) string {
		t.Helper()
		connectorRouteGov = g
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, adminIdentity{PrincipalID: "route-admin", TenantID: tenant}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s %d %s", method, path, w.Code, w.Body)
		}
		return w.Body.String()
	}
	for _, path := range []string{"/admin/sites/site/networks", "/admin/connectors/site/routes"} {
		call(a, "a", "POST", path, `{"action":"add","fqdn":"a.test"}`, 200)
		call(b, "b", "POST", path, `{"action":"add","fqdn":"b.test"}`, 200)
		if !strings.Contains(call(b, "a", "GET", path, "", 200), "a.test") {
			t.Fatal("peer route missing")
		}
		call(b, "a", "POST", path, `{"action":"add","fqdn":"a.test","description":"edited"}`, 200)
		if !strings.Contains(call(a, "a", "GET", path, "", 200), "edited") {
			t.Fatal("peer edit missing")
		}
		call(a, "a", "POST", path, `{"action":"remove","fqdn":"a.test"}`, 200)
		if strings.Contains(call(b, "a", "GET", path, "", 200), "a.test") {
			t.Fatal("deleted route remains")
		}
		if !strings.Contains(call(a, "b", "GET", path, "", 200), "b.test") {
			t.Fatal("other tenant lost")
		}
	}
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	call(a, "a", "GET", "/admin/sites/site/networks", "", 503)
	call(b, "a", "POST", "/admin/sites/site/networks", `{"action":"add","fqdn":"a.test"}`, 500)
}
func TestRouteDistributionWireAndRestart(t *testing.T) {
	for _, raw := range []string{`{"complete":true}`, `{"complete":true,"authored":{}}`} {
		var s governancePersistState
		if json.Unmarshal([]byte(raw), &s) == nil {
			t.Fatal("incomplete authoritative wire accepted")
		}
	}
	p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "received.json")}
	g := newConnectorRouteGovernanceWithPersister("", true, p)
	if err := g.AddAuthored("a", "site", authoredRoute{FQDN: "a.test"}); err != nil {
		t.Fatal(err)
	}
	if err := g.ImportReceived(context.Background(), &governancePersistState{}); err != nil {
		t.Fatal(err)
	}
	if g.CountForTenant("a") != 1 {
		t.Fatal("legacy empty cleared routes")
	}
	authority := newConnectorRouteGovernance()
	if err := authority.AddAuthored("a", "site", authoredRoute{FQDN: "a.test"}); err != nil {
		t.Fatal(err)
	}
	authority.RemoveTenant("a")
	wire, err := json.Marshal(authority.ExportForBundle())
	if err != nil {
		t.Fatal(err)
	}
	var received governancePersistState
	if err = json.Unmarshal(wire, &received); err != nil {
		t.Fatal(err)
	}
	if err = g.ImportReceived(context.Background(), &received); err != nil {
		t.Fatal(err)
	}
	if newConnectorRouteGovernanceWithPersister("", true, p).CountForTenant("a") != 0 {
		t.Fatal("restart resurrected erased routes")
	}
}

func TestRouteDistributionBundleHTTPDeletion(t *testing.T) {
	prior := connectorRouteGov
	defer func() { connectorRouteGov = prior }()
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: policy.NewStore(nil), AdminAuth: newAdminAuthStore()})
	authority := newConnectorRouteGovernance()
	connectorRouteGov = authority
	if err := authority.AddAuthored("tenant_northwind", "site", authoredRoute{FQDN: "gone.test"}); err != nil {
		t.Fatal(err)
	}
	read := func() configBundlePayload {
		t.Helper()
		r := doAdmin(t, h, "GET", "/admin/config-bundle", "")
		if r.Code != 200 {
			t.Fatal(r.Code, r.Body)
		}
		var b configBundlePayload
		if err := json.Unmarshal(r.Body.Bytes(), &b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	first := read()
	if first.RouteGovernance == nil || !first.RouteGovernance.Complete {
		t.Fatal("complete route snapshot absent")
	}
	if n, err := authority.RemoveTenantChecked("tenant_northwind"); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	last := read()
	if last.Generation <= first.Generation || last.RouteGovernance == nil || !last.RouteGovernance.Complete {
		t.Fatal("deletion missing from HTTP bundle")
	}
	receiver := newConnectorRouteGovernance()
	if err := receiver.ImportReceived(context.Background(), first.RouteGovernance); err != nil {
		t.Fatal(err)
	}
	if receiver.CountForTenant("tenant_northwind") != 1 {
		t.Fatal("initial route absent")
	}
	if err := receiver.ImportReceived(context.Background(), last.RouteGovernance); err != nil {
		t.Fatal(err)
	}
	if receiver.CountForTenant("tenant_northwind") != 0 {
		t.Fatal("HTTP deletion not applied")
	}
}

func TestRouteDistributionReceiverStoreRole(t *testing.T) {
	db := &sql.DB{}
	p, err := routeGovernancePersisterForRole("", db, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(routeGovernanceUpdater); !ok {
		t.Fatal("CP did not select shared authority")
	}
	p, err = routeGovernancePersisterForRole("", db, "https://cp.example.test")
	if err != nil || p != nil {
		t.Fatal("receiver selected authority", err)
	}
	for _, value := range []string{"postgres", cpStateBlobPersisterImportPrefix + "unused"} {
		if _, err := routeGovernancePersisterForRole(value, db, "https://cp.example.test"); err == nil {
			t.Fatal("explicit receiver authority accepted")
		}
	}
}
