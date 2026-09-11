package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

// TestAdminSiteStoreCRUDIsTenantScoped pins the core Slice 1b invariant: Sites are persisted, tenant-scoped, and
// one tenant can never see/get/delete another tenant's Sites.
func TestAdminSiteStoreCRUDIsTenantScoped(t *testing.T) {
	ctx := context.Background()
	store := newAdminSiteStore()
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)

	if _, err := store.Upsert(ctx, adminSiteModel{SiteID: "tokyo-dc", TenantID: "tenant_lab_001", Name: "Tokyo DC", Region: "ap-northeast-1", ExpectedConnectorCount: 2}, now); err != nil {
		t.Fatalf("upsert tokyo-dc: %v", err)
	}
	if _, err := store.Upsert(ctx, adminSiteModel{SiteID: "osaka-dc", TenantID: "tenant_lab_001"}, now); err != nil {
		t.Fatalf("upsert osaka-dc: %v", err)
	}
	if _, err := store.Upsert(ctx, adminSiteModel{SiteID: "secret-dc", TenantID: "tenant_other_001"}, now); err != nil {
		t.Fatalf("upsert other tenant: %v", err)
	}

	labSites, err := store.List(ctx, "tenant_lab_001")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(labSites) != 2 {
		t.Fatalf("lab sites = %d, want 2 (tokyo+osaka), got %#v", len(labSites), labSites)
	}
	for _, s := range labSites {
		if s.TenantID != "tenant_lab_001" {
			t.Fatalf("cross-tenant site leaked into list: %#v", s)
		}
	}

	// Cross-tenant Get must miss (fail-closed): tenant_lab_001 cannot read tenant_other's site.
	if _, ok, err := store.Get(ctx, "tenant_lab_001", "secret-dc"); err != nil || ok {
		t.Fatalf("cross-tenant Get = ok %v err %v, want not-found", ok, err)
	}
	// Cross-tenant Delete is a no-op (does not remove the other tenant's site).
	if err := store.Delete(ctx, "tenant_lab_001", "secret-dc"); err != nil {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	if _, ok, _ := store.Get(ctx, "tenant_other_001", "secret-dc"); !ok {
		t.Fatal("cross-tenant delete wrongly removed the other tenant's site")
	}

	// Own-tenant delete works and is idempotent.
	if err := store.Delete(ctx, "tenant_lab_001", "osaka-dc"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := store.Delete(ctx, "tenant_lab_001", "osaka-dc"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	if _, ok, _ := store.Get(ctx, "tenant_lab_001", "osaka-dc"); ok {
		t.Fatal("osaka-dc still present after delete")
	}
}

// TestAdminSiteFileStoreDurable confirms the file backend survives a reconstruction (restart-resilience).
func TestAdminSiteFileStoreDurable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sites.json")
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	store := newDurableAdminSiteStore(path)
	if _, err := store.Upsert(ctx, adminSiteModel{SiteID: "tokyo-dc", TenantID: "tenant_lab_001", Name: "Tokyo DC"}, now); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("snapshot not written: %v", err)
	}
	reloaded := newDurableAdminSiteStore(path)
	site, ok, err := reloaded.Get(ctx, "tenant_lab_001", "tokyo-dc")
	if err != nil || !ok {
		t.Fatalf("reloaded Get = ok %v err %v", ok, err)
	}
	if site.Name != "Tokyo DC" {
		t.Fatalf("reloaded site = %#v, want Name Tokyo DC", site)
	}
}

// TestAdminSiteListMergedAppliesMetaAndExpectedHealth covers the projection merge: persistent metadata
// is overlaid, and an online count below the expected count is degraded even when every present connector is up.
func TestAdminSiteListMergedAppliesMetaAndExpectedHealth(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-30 * time.Second).Format(time.RFC3339)

	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "c1", TenantID: "tenant_lab_001", ConnectorGroupID: "tokyo-dc", EdgeRegionID: "jp", PrivateBaseURL: "http://c1-private.example.test", LastHeartbeatAt: fresh, Status: "healthy"}, now); err != nil {
		t.Fatalf("register c1: %v", err)
	}

	store := newAdminSiteStore()
	// tokyo-dc: 1 connector online, expected 2 -> degraded (failover capacity below target).
	if _, err := store.Upsert(ctx, adminSiteModel{SiteID: "tokyo-dc", TenantID: "tenant_lab_001", Name: "Tokyo DC", Region: "ap-northeast-1", ExpectedConnectorCount: 2, RoutingNamespace: "site-tokyo"}, now); err != nil {
		t.Fatalf("upsert tokyo-dc: %v", err)
	}
	// new-dc: persistent Site, no connector yet, expected 1 -> down (0 online).
	if _, err := store.Upsert(ctx, adminSiteModel{SiteID: "new-dc", TenantID: "tenant_lab_001", ExpectedConnectorCount: 1}, now); err != nil {
		t.Fatalf("upsert new-dc: %v", err)
	}

	tunnelStatus := func(string) *bool { return nil } // unknown tunnel -> heartbeat freshness decides

	resp, err := adminSiteListMerged(ctx, registry, store, "tenant_lab_001", tunnelStatus, now)
	if err != nil {
		t.Fatalf("merged list: %v", err)
	}
	byID := map[string]adminSite{}
	for _, s := range resp.Sites {
		byID[s.SiteID] = s
	}

	tokyo, ok := byID["tokyo-dc"]
	if !ok {
		t.Fatalf("missing tokyo-dc: %#v", resp.Sites)
	}
	if !tokyo.Managed || tokyo.Name != "Tokyo DC" || tokyo.Region != "ap-northeast-1" || tokyo.ExpectedConnectorCount != 2 || tokyo.RoutingNamespace != "site-tokyo" {
		t.Fatalf("tokyo-dc meta not merged: %#v", tokyo)
	}
	if tokyo.ConnectorCount != 1 || tokyo.OnlineCount != 1 {
		t.Fatalf("tokyo-dc counts = %d/%d, want 1/1 from projection", tokyo.OnlineCount, tokyo.ConnectorCount)
	}
	if tokyo.Health != "degraded" {
		t.Fatalf("tokyo-dc health = %q, want degraded (1 online < 2 expected)", tokyo.Health)
	}

	newDC, ok := byID["new-dc"]
	if !ok {
		t.Fatalf("persistent-only site new-dc missing: %#v", resp.Sites)
	}
	if newDC.ConnectorCount != 0 || newDC.Health != "down" {
		t.Fatalf("new-dc = %#v, want 0 connectors / down (expected 1, 0 online)", newDC)
	}
}

// TestAdminSiteHealthWithExpected pins the expected-aware health boundaries.
func TestAdminSiteHealthWithExpected(t *testing.T) {
	cases := []struct {
		total, online, expected int
		want                    string
	}{
		{0, 0, 0, "unknown"},  // no expected -> population health (0,0) unknown
		{2, 2, 0, "healthy"},  // no expected -> population health
		{0, 0, 1, "down"},     // expected, none online
		{2, 1, 2, "degraded"}, // expected, below target
		{2, 2, 2, "healthy"},  // expected, at target
		{3, 3, 2, "healthy"},  // expected, above target
	}
	for _, tc := range cases {
		if got := adminSiteHealthWithExpected(tc.total, tc.online, tc.expected); got != tc.want {
			t.Fatalf("adminSiteHealthWithExpected(%d,%d,%d) = %q, want %q", tc.total, tc.online, tc.expected, got, tc.want)
		}
	}
}

// TestAdminSiteEnrollmentCommandIssuesOnceAndStoresHashOnly confirms the bootstrap secret is returned once, the
// command embeds it, and only the HASH is persisted (the plaintext is never recoverable from the store).
func TestAdminSiteEnrollmentCommandIssuesOnceAndStoresHashOnly(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	store := newAdminSiteStore()
	if _, err := store.Upsert(ctx, adminSiteModel{SiteID: "tokyo-dc", TenantID: "tenant_lab_001"}, now); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// A projection-only site (no persisted record yet) is AUTO-CREATED on enrollment, not 404'd — adding a
	// connector to a site shown in the Console must always work. The site then exists in the store.
	if _, ok, err := adminSiteEnrollmentCommandIssue(ctx, store, "tenant_lab_001", "projection-dc", enrollmentTokenParams{EdgeURL: "https://edge.example.com"}, now); err != nil || !ok {
		t.Fatalf("enroll for projection site = ok %v err %v, want auto-created", ok, err)
	}
	if _, ok, _ := store.Get(ctx, "tenant_lab_001", "projection-dc"); !ok {
		t.Fatal("projection site must be persisted after enrollment")
	}

	resp, ok, err := adminSiteEnrollmentCommandIssue(ctx, store, "tenant_lab_001", "tokyo-dc", enrollmentTokenParams{EdgeURL: "https://edge.example.com"}, now)
	if err != nil || !ok {
		t.Fatalf("enroll = ok %v err %v", ok, err)
	}
	if strings.TrimSpace(resp.BootstrapSecret) == "" {
		t.Fatal("bootstrap secret is empty")
	}
	// The command is one self-contained line: a --token (which carries the coordinates) + --state-dir.
	for _, want := range []string{"dsse-connector", "--token " + resp.Token, "--state-dir"} {
		if !strings.Contains(resp.Command, want) {
			t.Fatalf("command missing %q:\n%s", want, resp.Command)
		}
	}
	// The token decodes to the Site coordinates + the one-time bootstrap secret.
	rawTok, derr := base64.RawURLEncoding.DecodeString(resp.Token)
	if derr != nil {
		t.Fatalf("token base64: %v", derr)
	}
	var tok struct{ EdgeURL, TenantID, Site, Bootstrap string }
	if err := json.Unmarshal(rawTok, &struct {
		EdgeURL   *string `json:"edge_url"`
		TenantID  *string `json:"tenant_id"`
		Site      *string `json:"site"`
		Bootstrap *string `json:"bootstrap"`
	}{&tok.EdgeURL, &tok.TenantID, &tok.Site, &tok.Bootstrap}); err != nil {
		t.Fatalf("token json: %v", err)
	}
	if tok.EdgeURL != "https://edge.example.com" || tok.TenantID != "tenant_lab_001" || tok.Site != "tokyo-dc" || tok.Bootstrap != resp.BootstrapSecret {
		t.Fatalf("token payload wrong: %+v", tok)
	}

	// Persisted: hash only, never the plaintext.
	site, _, err := store.Get(ctx, "tenant_lab_001", "tokyo-dc")
	if err != nil {
		t.Fatalf("get after enroll: %v", err)
	}
	if site.BootstrapSecretHash != connectorRuntimeSecretHash(resp.BootstrapSecret) {
		t.Fatalf("stored hash = %q, want hash of issued secret", site.BootstrapSecretHash)
	}
	if strings.Contains(site.BootstrapSecretHash, resp.BootstrapSecret) {
		t.Fatal("stored hash contains the plaintext secret")
	}
	if site.BootstrapSecretRotatedAt == nil {
		t.Fatal("rotated-at not stamped")
	}

	// A client-supplied hash on a plain Upsert must be ignored / not overwrite the issued one.
	site.BootstrapSecretHash = ""
	if _, err := store.Upsert(ctx, adminSiteModel{SiteID: "tokyo-dc", TenantID: "tenant_lab_001", Name: "Renamed"}, now); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	after, _, _ := store.Get(ctx, "tenant_lab_001", "tokyo-dc")
	if after.BootstrapSecretHash != connectorRuntimeSecretHash(resp.BootstrapSecret) {
		t.Fatalf("plain upsert wiped the bootstrap hash: %#v", after)
	}
}

// TestAdminSiteAPISecretSafeAndLabInvariant exercises the HTTP surface: CRUD + enroll, secret-safe responses, and
// the lab invariant that with no persistent Sites GET /admin/sites is the unchanged Slice 1 projection.
func TestAdminSiteAPISecretSafeAndLabInvariant(t *testing.T) {
	registry := seedAdminSiteRegistry(t)
	siteStore := newAdminSiteStore()
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  registry,
		SiteStore: siteStore,
		AdminAuth: newAdminAuthStore(),
		// An enrollment command is refused unless this node knows the Edge transport CA a connector should
		// pin — a connector's first act is handing a CSR to something claiming to be its Edge, so an unpinned
		// first connection is the one that matters most. Set here because the node under test issues one.
		ConnectorEnrollmentEdgeCAPEM: "-----BEGIN CERTIFICATE-----\ntest-anchor\n-----END CERTIFICATE-----\n",
	})

	// Lab invariant: no persistent Sites yet -> identical to the Slice 1 projection (tokyo-dc + ungrouped).
	{
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/sites", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
		}
		var list adminSiteListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		if list.Count != 2 {
			t.Fatalf("projection-only count = %d, want 2 (tokyo-dc + ungrouped)", list.Count)
		}
		for _, s := range list.Sites {
			if s.Managed {
				t.Fatalf("projection-only site marked managed: %#v", s)
			}
		}
	}

	// Create a persistent Site.
	{
		rec := httptest.NewRecorder()
		body := strings.NewReader(`{"site_id":"tokyo-dc","name":"Tokyo DC","region":"ap-northeast-1","expected_connector_count":3}`)
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/sites", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
		}
		var detail adminSiteDetail
		if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
			t.Fatalf("decode create: %v", err)
		}
		if !detail.Managed || detail.Name != "Tokyo DC" || detail.ExpectedConnectorCount != 3 {
			t.Fatalf("created site = %#v, want managed Tokyo DC expected 3", detail.adminSite)
		}
		// tokyo-dc has 2 connectors in the seed, expected 3 -> degraded regardless of online state.
		if detail.Health != "degraded" && detail.Health != "down" {
			t.Fatalf("created tokyo-dc health = %q, want degraded/down (online < 3 expected)", detail.Health)
		}
	}

	// Enroll: bootstrap secret returned once; the persisted hash never appears in any response.
	var secret string
	{
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/sites/tokyo-dc/enrollment-command", strings.NewReader(`{"edge_url":"https://edge.example.com"}`)))
		if rec.Code != http.StatusOK {
			t.Fatalf("enroll status = %d body=%s", rec.Code, rec.Body.String())
		}
		var resp adminSiteEnrollmentCommandResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode enroll: %v", err)
		}
		secret = resp.BootstrapSecret
		// The command carries a --token (which encodes the secret), not the plaintext secret on the command line.
		if secret == "" || resp.Token == "" || !strings.Contains(resp.Command, resp.Token) {
			t.Fatalf("enroll response missing secret/token/command: %#v", resp)
		}
	}

	// The site detail must never leak the bootstrap secret hash or plaintext.
	{
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/sites/tokyo-dc", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("detail status = %d body=%s", rec.Code, rec.Body.String())
		}
		bodyText := rec.Body.String()
		if strings.Contains(bodyText, "bootstrap_secret_hash") || strings.Contains(bodyText, "sha256:") || strings.Contains(bodyText, secret) {
			t.Fatalf("site detail leaked bootstrap secret material: %s", bodyText)
		}
	}

	// Delete the persistent Site; it falls back to the projection-only Site (connectors remain).
	{
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/admin/sites/tokyo-dc", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("delete status = %d body=%s", rec.Code, rec.Body.String())
		}
		if _, ok, _ := siteStore.Get(context.Background(), "tenant_lab_001", "tokyo-dc"); ok {
			t.Fatal("persistent site still present after delete")
		}
		listRec := httptest.NewRecorder()
		handler.ServeHTTP(listRec, httptest.NewRequest(http.MethodGet, "/admin/sites", nil))
		var list adminSiteListResponse
		_ = json.Unmarshal(listRec.Body.Bytes(), &list)
		for _, s := range list.Sites {
			if s.SiteID == "tokyo-dc" && s.Managed {
				t.Fatalf("tokyo-dc still managed after delete: %#v", s)
			}
		}
	}
}

// TestAdminSiteSlice1bOpenAPIContract pins the Slice 1b additions to the admin OpenAPI contract.
func TestAdminSiteSlice1bOpenAPIContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi", "admin_api.yaml"))
	if err != nil {
		t.Fatalf("read admin OpenAPI contract: %v", err)
	}
	contract := string(data)
	for _, want := range []string{
		"    AdminSiteUpsertRequest:",
		"    AdminSiteEnrollmentCommand:",
		"  /admin/sites/{site_id}/enrollment-command:",
		`$ref: "#/components/schemas/AdminSiteUpsertRequest"`,
		`$ref: "#/components/schemas/AdminSiteEnrollmentCommand"`,
		"bootstrap_secret",
	} {
		if !strings.Contains(contract, want) {
			t.Fatalf("admin OpenAPI contract missing %q", want)
		}
	}
}

// ★★★ WHAT THE CUSTOMER IS HANDED IS AN INSTALLATION, NOT A PROCESS (2026-08-26, operator's instruction).
// The screen used to print `dsse-connector …`: a terminal process, gone at the next reboot, with no way to
// find out whether it worked. Gated here because this is one line in a string builder and the whole of the
// customer's path runs through it — a silent revert to the old line puts every new site back on the harder
// path, and nothing else in the tree would notice.
func TestTheEnrollmentScreenHandsOutAnInstallation(t *testing.T) {
	cmd := adminSiteEnrollmentCommand("TOKEN", "/var/lib/dsse-connector")
	if !strings.Contains(cmd, "dsse-connector-install") {
		t.Fatalf("the customer is handed a process rather than an installation:\n%s", cmd)
	}
	if !strings.Contains(cmd, "--token TOKEN") || !strings.Contains(cmd, "--state-dir /var/lib/dsse-connector") {
		t.Fatalf("the command lost a value the connector cannot start without:\n%s", cmd)
	}
	// And the half that tells the customer whether any of it worked. A connector holding one of its two doors
	// shows as Connected in the Console, so the check has to run on the machine.
	verify := adminSiteEnrollmentVerifyCommand("/var/lib/dsse-connector")
	if !strings.Contains(verify, "--verify") || !strings.Contains(verify, "--state-dir /var/lib/dsse-connector") {
		t.Fatalf("the customer is given no way to check what they installed: %q", verify)
	}
	// A state directory the operator chose has to reach BOTH commands: verifying somewhere the connector does
	// not live reports a machine that never enrolled.
	if elsewhere := adminSiteEnrollmentVerifyCommand("/srv/dsse"); !strings.Contains(elsewhere, "/srv/dsse") {
		t.Fatalf("the check ignores where this connector was actually installed: %q", elsewhere)
	}
}

// ★★★ THE FILE THE CUSTOMER DOWNLOADS AND THE PROGRAM THAT READS IT ARE TWO TREES (2026-08-26). The keys
// below are the contract between cmd/dsse-edge and cmd/dsse-connector-install; they cannot import each other,
// so a rename on either side is silent — the installer would refuse every profile this deployment issues with
// "not a connector install profile", or worse, read a profile whose door list it cannot see and install a
// connector with one region. The mirror of this test lives in cmd/dsse-connector-install/profile_test.go and
// parses the exact bytes asserted here.
func TestTheDownloadedProfileCarriesWhatTheInstallerReads(t *testing.T) {
	p := buildConnectorInstallProfile("t1", "tokyo-dc", "TOKEN", "2026-08-26T00:00:00Z", enrollmentTokenParams{
		EdgeEndpoints: "region-a=https://a.example:443;region-b=https://b.example:443",
		EdgeCAPEM:     "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
		StateDir:      "/var/lib/dsse-connector",
	})
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"kind", "tenant_id", "site", "edge_endpoints", "edge_ca", "state_dir", "token"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("the installer reads %q and this profile does not carry it: %s", key, raw)
		}
	}
	if got["kind"] != "dsse_connector_install_profile.v1" {
		t.Fatalf("the installer refuses any other kind by name: %v", got["kind"])
	}
	doors, _ := got["edge_endpoints"].([]any)
	if len(doors) != 2 {
		t.Fatalf("the profile carries every door, or the connector it installs cannot fail over: %v", doors)
	}
	// ★ THE FILE IS A CREDENTIAL UNTIL THE FIRST RUN, and it says so in itself — a screen says it once, a
	// file is copied, mailed, and left in a downloads folder.
	if note, _ := got["note"].(string); !strings.Contains(note, "credential") {
		t.Fatalf("the file does not say what it is: %q", note)
	}
}

// ★ THE SCREEN AND THE CONNECTOR MUST COUNT THE DOORS THE SAME WAY. cmd/dsse-connector accepts ';' ',' and a
// newline; this counted only ';', so a comma-separated pair displayed as ONE door beneath the warning about
// what a single door means, while the connector was failing over between two.
func TestTheDoorsAreCountedTheWayTheConnectorCountsThem(t *testing.T) {
	semi := enrollmentDoorList(enrollmentTokenParams{EdgeEndpoints: "region-a=https://a.example;region-b=https://b.example"})
	comma := enrollmentDoorList(enrollmentTokenParams{EdgeEndpoints: "region-a=https://a.example,region-b=https://b.example"})
	if len(semi) != 2 || len(comma) != 2 {
		t.Fatalf("the same pair counted %d one way and %d the other", len(semi), len(comma))
	}
	if only := enrollmentDoorList(enrollmentTokenParams{EdgeURL: "https://a.example"}); len(only) != 1 {
		t.Fatalf("a deployment with one address still has one door: %v", only)
	}
}
