package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/vlan"
)

// A Named Network created through another control plane must be bindable here:
// the binding route decided existence from this process's VLAN cache, so a
// Network the Networks page (which refreshes) listed was refused as "not a
// known Named Network" by the route that binds it.
func TestPostgresConnectorBindingSeesPeerNamedNetwork(t *testing.T) {
	a, _ := postgresFailureElectors(t)
	db, err := newCPStateBlobDB(os.Getenv("POSTGRES_QUEUE_E2E_DSN"), "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := postgresBlobPersister{db: db, key: "vlan_objects"}
	saved, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if saved != nil {
			p.Save(saved)
		} else {
			db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", p.key)
		}
	}()
	tenant := testEvaluator().PolicyBundle.TenantID
	now := time.Now()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "binding-admin", TenantID: tenant, Roles: []string{"admin", "super_admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "binding-session", TenantID: tenant, AdminPrincipalID: "binding-admin", Roles: []string{"admin", "super_admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "binding-csrf"}})
	w, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// newServerWithConfig builds the package-level route governance only when it is
	// nil, bound to this test's database. Restore it and the row it writes, so a
	// later test does not inherit a store whose database this test closes.
	oldDB, oldE, oldGov := cpStateBlobDB, cpLeaderElectorInstance, connectorRouteGov
	cpStateBlobDB, connectorRouteGov = db, nil
	defer func() {
		db.Exec("DELETE FROM cp_state_blobs WHERE store_key='connector_route_governance'")
		cpStateBlobDB, cpLeaderElectorInstance, connectorRouteGov = oldDB, oldE, oldGov
	}()
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: w, AdminAuth: auth, OperatorTenantID: tenant, VLANObjectStorePath: "postgres"})
	cpLeaderElectorInstance = a
	a.tick()

	// Another control plane creates the Network after this server loaded its cache.
	peer := vlan.NewStore()
	if e := peer.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if _, e := peer.UpsertObject(model.VLANObject{ID: "peer-net", TenantID: tenant, Class: "server", CIDRs: []string{"10.9.0.0/24"}}); e != nil {
		t.Fatal(e)
	}

	r := httptest.NewRequest("POST", "/admin/connectors/conn-1/routes", strings.NewReader(`{"action":"add","network_id":"peer-net"}`))
	r.AddCookie(&http.Cookie{Name: "admin_session", Value: "binding-session"})
	r.Header.Set("X-CSRF-Token", "binding-csrf")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code == http.StatusBadRequest && strings.Contains(rr.Body.String(), "not a known Named Network") {
		t.Fatalf("binding refused a Network that shared authority holds: %d %s", rr.Code, rr.Body)
	}
	t.Logf("binding response %d", rr.Code)
}
