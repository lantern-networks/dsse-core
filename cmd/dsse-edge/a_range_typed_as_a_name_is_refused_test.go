package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Found 2026-11-08 on acceptance C: "10.47.1.30/32" typed into a site's network field was sent as a name,
// accepted, listed as a name, and delivered to the connector as cidrs=[] fqdns=1 — a binding that matches
// nothing, made through the field beside the one that refuses a raw CIDR.
func TestARangeTypedAsANameIsRefusedOnBothBindingRoutes(t *testing.T) {
	prior := connectorRouteGov
	defer func() { connectorRouteGov = prior }()
	connectorRouteGov = newConnectorRouteGovernanceWithPersister("", true, nil)
	mux := http.NewServeMux()
	registerConnectorSiteAdminRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, serverConfig{}, testEvaluator(), nil, nil, nil, nil, nil, nil, nil, nil, nil, "", nil, func(context.Context, string, string) ([]string, []string, bool) { return nil, nil, true })
	post := func(path, body string) (int, string) {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, adminIdentity{PrincipalID: "admin", TenantID: "t"}))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	for _, path := range []string{"/admin/sites/site/networks", "/admin/connectors/site/routes"} {
		for _, typed := range []string{"10.47.1.30/32", "10.47.1.30", "fd00::1", "[fd00::1]", "10.0.0.0/8", "app.corp:8080"} {
			code, body := post(path, `{"action":"add","fqdn":"`+typed+`"}`)
			if code != http.StatusBadRequest || !strings.Contains(body, "Named Network") {
				t.Errorf("%s accepted %q as a name: %d %s", path, typed, code, body)
			}
		}
		if code, body := post(path, `{"action":"add","fqdn":"wiki.corp"}`); code != http.StatusOK {
			t.Errorf("%s refused a host name: %d %s", path, code, body)
		}
		// A binding stored before this rule can still be removed.
		if code, body := post(path, `{"action":"remove","fqdn":"10.47.1.30/32"}`); code == http.StatusBadRequest {
			t.Errorf("%s refuses to remove a legacy address-shaped name: %d %s", path, code, body)
		}
	}
}
