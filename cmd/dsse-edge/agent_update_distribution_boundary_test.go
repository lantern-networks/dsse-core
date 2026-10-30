package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

func TestFleetPullKeepsCaseDistinctCanariesAndCatalogueSeparate(t *testing.T) {
	now := time.Now().UTC()
	signer := updateSigner(t)
	keys := []string{pinnedKey(t, signer)}
	_, upper := signedUpdate(t, signer, "0.4.1", now)
	_, lower := signedUpdate(t, signer, "0.4.2", now)
	_, catalogue := signedUpdate(t, signer, "0.4.0", now)
	active := map[string]agentpolicy.Envelope{
		tenantTargetKey("Acme", "windows", "amd64"):                    upper,
		tenantTargetKey("acme", "windows", "amd64"):                    lower,
		tenantTargetKey(agentUpdateCatalogueScope, "windows", "amd64"): catalogue,
	}
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/agent-updates/distribution" {
			http.Error(w, "wrong distribution route", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "agent_update_distribution.v2",
			"tenant_id": agentUpdateCatalogueScope, "envelopes": active})
	}))
	defer cp.Close()
	src := agentUpdateSource{url: cp.URL, token: "test-fleet", client: cp.Client(), trustedKeys: keys}
	set, err := src.fetch(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	facing := &publishedUpdates{}
	facing.replace(set)
	for _, tc := range []struct{ tenant, version string }{{"Acme", "0.4.1"}, {"acme", "0.4.2"}, {"other", "0.4.0"}} {
		got, ok := facing.forTenantTarget(tc.tenant, "windows", "amd64")
		if !ok || got.Manifest.Version != tc.version {
			t.Fatalf("%s selected %q, found=%t", tc.tenant, got.Manifest.Version, ok)
		}
	}
	bad := map[string]agentpolicy.Envelope{tenantTargetKey("Acme", "darwin", "arm64"): upper}
	active = bad
	if _, err := src.fetch(context.Background(), now); err == nil {
		t.Fatal("manifest was adopted under a false target key")
	}
}

func TestDistributionArtifactReadRequiresFleetScopeAndExactPublication(t *testing.T) {
	now := time.Now().UTC()
	signer := updateSigner(t)
	keys := []string{pinnedKey(t, signer)}
	dir := t.TempDir()
	store := newPublishedAgentUpdateStore().WithArtifactDir(dir)
	for _, tc := range []struct{ tenant, version string }{{"Acme", "0.4.1"}, {"acme", "0.4.2"}} {
		m, env := signedUpdate(t, signer, tc.version, now)
		if _, _, _, err := store.Publish(tc.tenant, env, keys, now, func(agentupdate.Manifest) bool { return true }); err != nil {
			t.Fatal(err)
		}
		path := artifactStorePath(dir, tc.tenant, m.Platform, m.Arch, m.Version)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, artifactBytesFor(tc.version), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	registerAgentUpdateArtifactAdminRoutes(mux, func(_ string, fn http.HandlerFunc) http.HandlerFunc { return fn },
		store, keys, dir, false, nil, testEvaluator(), nil, "operator")
	ask := func(id adminIdentity, tenant string) *httptest.ResponseRecorder {
		q := url.Values{"platform": {"windows"}, "arch": {"amd64"}, "distribution_tenant_id": {tenant}}
		req := httptest.NewRequest(http.MethodGet, "/admin/agent-update-artifact?"+q.Encode(), nil)
		req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{}, id))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	fleet := adminIdentity{TenantID: "operator", AuthMethod: "admin_api_token", Roles: []string{"admin"},
		Scopes: []string{"admin.agents.read", "admin.agent_updates.distribution.read"}}
	for _, tc := range []struct{ tenant, version string }{{"Acme", "0.4.1"}, {"acme", "0.4.2"}} {
		rec := ask(fleet, tc.tenant)
		if rec.Code != http.StatusOK || rec.Body.String() != string(artifactBytesFor(tc.version)) {
			t.Fatalf("%s artifact response status=%d body=%q", tc.tenant, rec.Code, rec.Body.String())
		}
	}
	readOnly := fleet
	readOnly.Scopes = []string{"admin.agents.read"}
	if got := ask(readOnly, "Acme"); got.Code != http.StatusForbidden {
		t.Fatalf("read-only token fetched another tenant's bytes: %d", got.Code)
	}
	foreign := fleet
	foreign.TenantID = "customer"
	if got := ask(foreign, "Acme"); got.Code != http.StatusForbidden {
		t.Fatalf("customer token fetched another tenant's bytes: %d", got.Code)
	}
}

func TestFleetPullStoresCaseDistinctArtifactsWithoutOverwrite(t *testing.T) {
	now := time.Now().UTC()
	signer := updateSigner(t)
	keys := []string{pinnedKey(t, signer)}
	_, upper := signedUpdate(t, signer, "0.4.1", now)
	_, lower := signedUpdate(t, signer, "0.4.2", now)
	active := map[string]agentpolicy.Envelope{
		tenantTargetKey("Acme", "windows", "amd64"): upper,
		tenantTargetKey("acme", "windows", "amd64"): lower,
	}
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/agent-updates/distribution":
			writeJSON(w, http.StatusOK, map[string]any{"schema_version": "agent_update_distribution.v2",
				"tenant_id": agentUpdateCatalogueScope, "envelopes": active})
		case "/admin/agent-update-artifact":
			var version string
			var env agentpolicy.Envelope
			switch r.URL.Query().Get("distribution_tenant_id") {
			case "Acme":
				version, env = "0.4.1", upper
			case "acme":
				version, env = "0.4.2", lower
			default:
				http.Error(w, "wrong tenant", http.StatusForbidden)
				return
			}
			if r.URL.Query().Get("expected_manifest_sha256") != env.PayloadSHA256 {
				http.Error(w, "wrong manifest", http.StatusConflict)
				return
			}
			_, _ = w.Write(artifactBytesFor(version))
		default:
			http.NotFound(w, r)
		}
	}))
	defer cp.Close()
	src := agentUpdateSource{url: cp.URL, token: "test-fleet", client: cp.Client(), trustedKeys: keys,
		artifactDir: t.TempDir()}
	set, err := src.fetch(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	served := src.serveable(context.Background(), set, nil)
	if len(served) != 2 {
		t.Fatalf("only %d of 2 canaries became serveable", len(served))
	}
	for _, tc := range []struct{ tenant, version string }{{"Acme", "0.4.1"}, {"acme", "0.4.2"}} {
		path := artifactStorePath(src.artifactDir, tc.tenant, "windows", "amd64", tc.version)
		bytes, err := os.ReadFile(path)
		if err != nil || string(bytes) != string(artifactBytesFor(tc.version)) {
			t.Fatalf("%s artifact not isolated at its exact shelf: err=%v", tc.tenant, err)
		}
	}
}

func TestReleaseDistributionRequiresDeploymentFleetCredential(t *testing.T) {
	now := time.Now().UTC()
	signer := updateSigner(t)
	keys := []string{pinnedKey(t, signer)}
	store := newPublishedAgentUpdateStore()
	_, env := signedUpdate(t, signer, "0.4.3", now)
	if _, _, _, err := store.Publish("customer", env, keys, now, func(agentupdate.Manifest) bool { return true }); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	gate := func(permission string, next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			id, ok := adminIdentityFromRequest(r)
			if !ok || !adminPermissionAllowed(id.Roles, permission) || !adminScopeAllowed(id, permission) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next(w, r)
		}
	}
	registerAgentUpdatePublishRoutes(mux, gate, store, keys, false, nil, testEvaluator(), "", nil, nil, nil, "operator")
	ask := func(id adminIdentity, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{}, id))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	readOnly := adminIdentity{TenantID: "operator", AuthMethod: "admin_api_token", Roles: []string{"admin"}, Scopes: []string{"admin.agents.read"}}
	if got := ask(readOnly, "/admin/agent-updates/distribution"); got.Code != http.StatusForbidden {
		t.Fatalf("ordinary read credential obtained all tenants: %d", got.Code)
	}
	foreign := adminIdentity{TenantID: "customer", AuthMethod: "admin_api_token", Roles: []string{"admin"}, Scopes: []string{"admin.agents.read", "admin.agent_updates.distribution.read"}}
	if got := ask(foreign, "/admin/agent-updates/distribution"); got.Code != http.StatusForbidden {
		t.Fatalf("customer token obtained all tenants: %d", got.Code)
	}
	session := adminIdentity{TenantID: "operator", AuthMethod: "admin_session", Roles: []string{"admin"}}
	if got := ask(session, "/admin/agent-updates/distribution"); got.Code != http.StatusForbidden {
		t.Fatalf("browser session obtained all tenants: %d", got.Code)
	}
	fleet := adminIdentity{TenantID: "operator", AuthMethod: "admin_api_token", Roles: []string{"admin"}, Scopes: []string{"admin.agents.read", "admin.agent_updates.distribution.read"}}
	got := ask(fleet, "/admin/agent-updates/distribution")
	if got.Code != http.StatusOK {
		t.Fatalf("fleet token refused: %d %s", got.Code, got.Body.String())
	}
	var body struct {
		Envelopes map[string]agentpolicy.Envelope `json:"envelopes"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Envelopes) != 1 {
		t.Fatalf("fleet distribution has %d releases", len(body.Envelopes))
	}
	if got := ask(foreign, "/admin/agent-updates"); got.Code != http.StatusOK {
		t.Fatalf("customer own view refused: %d", got.Code)
	}
}

func TestDeviceUpdateManifestSelectsExactCertificateTenantAndCatalogue(t *testing.T) {
	_, reg, _, _ := tenantCARoutesForTest(t)
	upperCA, upperPEM := tenantCATestCA(t, "Upper Device CA")
	lowerCA, lowerPEM := tenantCATestCA(t, "Lower Device CA")
	otherCA, otherPEM := tenantCATestCA(t, "Other Device CA")
	for tenant, pem := range map[string][]byte{"Acme": upperPEM, "acme": lowerPEM, "other": otherPEM} {
		if _, err := reg.Register(tenant, pem); err != nil {
			t.Fatal(err)
		}
	}
	facing := &publishedUpdates{byTarget: map[string]publishedUpdate{
		tenantTargetKey("Acme", "darwin", "arm64"):                    {Manifest: agentupdate.Manifest{Version: "0.4.1", Platform: "darwin", Arch: "arm64"}, Envelope: agentpolicy.Envelope{PayloadSHA256: "upper"}, TenantID: "Acme"},
		tenantTargetKey("acme", "darwin", "arm64"):                    {Manifest: agentupdate.Manifest{Version: "0.4.2", Platform: "darwin", Arch: "arm64"}, Envelope: agentpolicy.Envelope{PayloadSHA256: "lower"}, TenantID: "acme"},
		tenantTargetKey(agentUpdateCatalogueScope, "darwin", "arm64"): {Manifest: agentupdate.Manifest{Version: "0.4.0", Platform: "darwin", Arch: "arm64"}, Envelope: agentpolicy.Envelope{PayloadSHA256: "catalogue"}, TenantID: agentUpdateCatalogueScope},
	}}
	mux := http.NewServeMux()
	registerSteerAgentUpdateRoutes(mux, serverConfig{PublishedUpdates: facing, TenantCARegistry: reg})
	ask := func(ca *x509.Certificate) string {
		req := httptest.NewRequest(http.MethodGet, "/steer/agent-update-manifest?platform=darwin&arch=arm64", nil)
		leaf := leafOf("device-1")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("tenant device refused: %d %s", rec.Code, rec.Body.String())
		}
		var env agentpolicy.Envelope
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		return env.PayloadSHA256
	}
	if got := ask(upperCA); got != "upper" {
		t.Fatalf("Acme received %q", got)
	}
	if got := ask(lowerCA); got != "lower" {
		t.Fatalf("acme received %q", got)
	}
	if got := ask(otherCA); got != "catalogue" {
		t.Fatalf("other tenant did not get explicit catalogue: %q", got)
	}
}

func TestDeviceUpdateArtifactUsesTheSelectedTenantShelf(t *testing.T) {
	_, reg, _, _ := tenantCARoutesForTest(t)
	upperCA, upperPEM := tenantCATestCA(t, "Upper Update CA")
	lowerCA, lowerPEM := tenantCATestCA(t, "Lower Update CA")
	for tenant, pem := range map[string][]byte{"Acme": upperPEM, "acme": lowerPEM} {
		if _, err := reg.Register(tenant, pem); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	facing := &publishedUpdates{byTarget: map[string]publishedUpdate{}}
	for _, tc := range []struct{ tenant, body string }{{"Acme", "upper signed bytes"}, {"acme", "lower signed bytes"}} {
		body := []byte(tc.body)
		sum := sha256.Sum256(body)
		m := agentupdate.Manifest{Platform: "darwin", Arch: "arm64", Version: "0.4.1",
			ArtifactSize: int64(len(body)), ArtifactSHA256: hex.EncodeToString(sum[:])}
		path := artifactStorePath(dir, tc.tenant, m.Platform, m.Arch, m.Version)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		facing.byTarget[tenantTargetKey(tc.tenant, m.Platform, m.Arch)] = publishedUpdate{Manifest: m, TenantID: tc.tenant}
	}
	mux := http.NewServeMux()
	registerSteerAgentUpdateArtifactRoute(mux, serverConfig{TenantCARegistry: reg,
		PublishedUpdates: facing, AgentUpdateArtifactDir: dir})
	for _, tc := range []struct {
		ca   *x509.Certificate
		body string
	}{{upperCA, "upper signed bytes"}, {lowerCA, "lower signed bytes"}} {
		req := httptest.NewRequest(http.MethodGet, "/steer/agent-update-artifact?platform=darwin&arch=arm64", nil)
		leaf := leafOf("device-1")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, tc.ca}}}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Body.String() != tc.body {
			t.Fatalf("device saw another tenant's package: status=%d body=%q", rec.Code, rec.Body.String())
		}
	}
}
