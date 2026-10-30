package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/authportal"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

// Opt-in live harness: runs the production broker/gate against an operator's
// isolated Keycloak. Ordinary unit tests do not start a server or need secrets.
// Browser automation drives the three loopback doors, then POSTs finish.
func TestKeycloakLiveBrowserHarness(t *testing.T) {
	dir := os.Getenv("DSSE_KEYCLOAK_STATE_DIR")
	if dir == "" {
		t.Skip("live Keycloak browser acceptance is opt-in")
	}
	if os.Getenv("DSSE_KEYCLOAK_HOSTS_TLS") != "1" {
		t.Fatal("browser authentication requires the isolated HTTPS fixture and trusted local CA")
	}
	registry := idpregistry.NewStore()
	for _, tenant := range []string{"momiji", "kaede"} {
		raw, err := os.ReadFile(filepath.Join(dir, tenant+"-idp-connection.private.json"))
		if err != nil {
			t.Fatal(err)
		}
		var conn idpregistry.Connection
		if err = json.Unmarshal(raw, &conn); err != nil {
			t.Fatal(err)
		}
		conn.TenantID = "tenant_" + tenant
		if conn.Issuer != "http://localhost:18080/realms/dsse-"+tenant && conn.Issuer != "https://idp.dsse.test:18443/realms/dsse-"+tenant {
			t.Fatal("isolated loopback issuer required")
		}
		if _, err = registry.Upsert(conn); err != nil {
			t.Fatal(err)
		}
	}
	signer, err := newDeviceBindingSigner()
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	done := make(chan struct{})
	for i, node := range []string{"A", "B", "C"} {
		port := 18181 + i
		self := "http://localhost:" + strconv.Itoa(port)
		if os.Getenv("DSSE_KEYCLOAK_HOSTS_TLS") == "1" {
			self = "https://edge-" + string(rune('a'+i)) + ".portal.dsse.test:18443"
		}
		store := grantstore.NewStore()
		broker := newClientlessBroker(registry, store, &http.Client{Timeout: 10 * time.Second}, self, "operator", time.Hour, signer)
		gate := &federatedAuthGate{grants: store, tenantID: "operator"}
		mux := http.NewServeMux()
		broker.register(mux)
		mux.HandleFunc("GET /acceptance/start", func(w http.ResponseWriter, r *http.Request) {
			tenant := r.URL.Query().Get("tenant")
			if tenant != "momiji" && tenant != "kaede" {
				http.Error(w, "unknown fixture", 400)
				return
			}
			device := "device-" + node
			tid := "tenant_" + tenant
			q := url.Values{"idp": {"keycloak-" + tenant}, "tenant": {tid}, "device": {device}, "device_sig": {signer.signBinding(device, tid)}, "acr": {r.URL.Query().Get("acr")}}
			origin, err := authportal.Origin(self)
			if err != nil {
				t.Fatal(err)
			}
			q.Set("portal_origin", origin)
			q.Set("return_to", "ssh.internal:22")
			q.Set("amr", "pwd")
			if q.Get("acr") == "2" {
				q.Set("amr", "pwd,otp")
			}
			q.Set("max_age", "300")
			if err := addAuthStartLifetime(q, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			q.Set("requirements_sig", signer.signRequirements(q))
			if r.URL.Query().Get("tamper") == "device" {
				q.Set("device", "different-device")
			}
			if owner := r.URL.Query().Get("callback_owner"); owner != "" || r.URL.Query().Get("downgrade") == "true" {
				rec := httptest.NewRecorder()
				broker.startForTest(rec, httptest.NewRequest("GET", "/clientless/auth/start?"+q.Encode(), nil))
				if rec.Code != http.StatusFound {
					http.Error(w, "start failed", rec.Code)
					return
				}
				for _, cookie := range rec.Result().Cookies() {
					http.SetCookie(w, cookie)
				}
				target, err := url.Parse(rec.Header().Get("Location"))
				if err != nil {
					http.Error(w, "invalid redirect", 500)
					return
				}
				query := target.Query()
				if owner != "" {
					ports := map[string]int{"A": 18181, "B": 18182, "C": 18183}
					n, ok := ports[owner]
					if !ok {
						http.Error(w, "unknown owner", 400)
						return
					}
					callback := "http://localhost:" + strconv.Itoa(n) + "/clientless/auth/callback"
					if os.Getenv("DSSE_KEYCLOAK_HOSTS_TLS") == "1" {
						callback = "https://edge-" + string(rune('a'+n-18181)) + ".portal.dsse.test:18443/clientless/auth/callback"
					}
					query.Set("redirect_uri", callback)
				}
				if r.URL.Query().Get("downgrade") == "true" {
					query.Set("acr_values", "1")
				}
				target.RawQuery = query.Encode()
				http.Redirect(w, r, target.String(), http.StatusFound)
				return
			}
			http.Redirect(w, r, "/clientless/auth/start?"+q.Encode(), http.StatusFound)
		})
		mux.HandleFunc("GET /acceptance/status", func(w http.ResponseWriter, r *http.Request) {
			rows := []map[string]any{}
			for _, g := range store.ListAll() {
				rows = append(rows, map[string]any{"tenant": g.TenantID, "device": g.DeviceID, "acr": g.ACR, "email": g.UserEmail, "revoked": g.Revoked, "amr": g.AMR, "auth_time": g.AuthTime, "scope": g.Scope})
			}
			age := int64(300)
			requirements := federatedRequirements{OSPrincipal: testAuthPrincipal, OSSession: testAuthSession, IdP: "keycloak-momiji", ACR: "2", AMR: []string{"pwd", "otp"}, MaxAgeSeconds: &age, Scope: "ssh.internal:22"}
			otherDest := requirements
			otherDest.Scope = "different.internal:22"
			wrongMethod := requirements
			wrongMethod.AMR = []string{"phr"}
			check := func(tenant, device, acr, provider string) bool {
				return gate.hasLiveGrantWithRequirements(tenant, device, federatedRequirements{Scope: "ssh.internal:22", ACR: acr, IdP: provider})
			}
			writeJSON(w, 200, map[string]any{
				"scoped_mfa":        gate.hasLiveGrantWithRequirements("tenant_momiji", "device-"+node, requirements),
				"wrong_destination": gate.hasLiveGrantWithRequirements("tenant_momiji", "device-"+node, otherDest),
				"wrong_method":      gate.hasLiveGrantWithRequirements("tenant_momiji", "device-"+node, wrongMethod),
				"node":              node, "grants": rows,
				"momiji_baseline":    check("tenant_momiji", "device-"+node, "1", "keycloak-momiji"),
				"momiji_mfa":         check("tenant_momiji", "device-"+node, "2", "keycloak-momiji"),
				"wrong_provider_mfa": check("tenant_momiji", "device-"+node, "2", "keycloak-kaede"),
				"other_device_mfa":   check("tenant_momiji", "different-device", "2", "keycloak-momiji"),
				"unbound_mfa":        check("tenant_momiji", "", "2", "keycloak-momiji"),
				"kaede_mfa":          check("tenant_kaede", "device-"+node, "2", "keycloak-kaede"),
			})
		})
		mux.HandleFunc("POST /acceptance/revoke", func(w http.ResponseWriter, r *http.Request) {
			for _, g := range store.ListAll() {
				if _, _, err := store.RevokeForTenant(g.TenantID, g.GrantID); err != nil {
					http.Error(w, "revoke failed", 500)
					return
				}
			}
			w.WriteHeader(204)
		})
		mux.HandleFunc("POST /acceptance/finish", func(w http.ResponseWriter, r *http.Request) { once.Do(func() { close(done) }); w.WriteHeader(204) })
		listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go srv.Serve(listener)
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		})
	}
	ready, _ := json.Marshal(map[string]any{"run_id": time.Now().UTC().Format(time.RFC3339Nano), "ports": []int{18181, 18182, 18183}, "scope": "production broker and gate with trusted hosts HTTPS when enabled; three instances in one process, not AWS or OS acceptance"})
	if err := os.WriteFile(filepath.Join(dir, "browser-harness-ready.json"), ready, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(15 * time.Minute):
		t.Fatal("browser acceptance did not finish before harness deadline")
	}
}
