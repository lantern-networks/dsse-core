package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func publishedAppForDistribution(tenant, destination string) appcatalog.Entry {
	return appcatalog.Entry{ApplicationID: "same-app", TenantID: tenant, Name: "Private test app", ApplicationType: "private_app", Status: "active", Published: true, Destination: destination, DestinationPort: 18081, PublishProtocol: "web", ConnectorGroupID: tenant + "-site"}
}

func TestApplicationBundleSignedFleetPublicationAndDeletion(t *testing.T) {
	previous := operatorTenantConfigured()
	t.Cleanup(func() { operatorTenantAuthority.Store(previous) })
	auth := newAdminAuthStore()
	for _, tenant := range []string{"operator", "customer"} {
		auth.UpsertPrincipal(adminPrincipal{ID: tenant, TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
		auth.UpsertAPIToken(adminAPIToken{ID: tenant, TenantID: tenant, TokenHash: adminTokenHash("token-" + tenant), Roles: []string{"admin"}, Scopes: []string{"admin.policy.read"}, CreatedByAdminPrincipalID: tenant, Status: "active", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)})
	}
	store := appcatalog.NewStore()
	for tenant, destination := range map[string]string{"customer": "10.50.1.1", "other": "10.60.1.1"} {
		if _, err := store.Upsert(context.Background(), publishedAppForDistribution(tenant, destination), tenant, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, OperatorTenantID: "operator", ApplicationCatalogStore: store, AgentPolicySigner: signer}))
	defer server.Close()
	source := configBundleSource{url: server.URL, client: server.Client(), token: "token-operator", tenantID: "operator", verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	edge := appcatalog.NewStore()
	targets := configApplyTargets{rules: policyrule.NewStore(), applications: edge, policyStore: policy.NewStore(nil), dlp: dlpStoresForTest("applications")}
	fetch := func() configBundlePayload {
		t.Helper()
		bundle, err := source.fetch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !bundle.signatureVerified {
			t.Fatal("signature not verified")
		}
		if _, err := source.apply(bundle, targets); err != nil {
			t.Fatal(err)
		}
		return bundle
	}
	first := fetch()
	for tenant, destination := range map[string]string{"customer": "10.50.1.1", "other": "10.60.1.1"} {
		entry, ok, err := edge.Get(context.Background(), tenant, "same-app")
		if err != nil || !ok || entry.Destination != destination {
			t.Fatalf("tenant route missing: %s %+v %v", tenant, entry, err)
		}
		profile := edgeplane.RouteProfilesWithPublishedCatalog(nil, edge, tenant)["same-app"]
		if profile.Destination != destination || profile.DestinationPort != 18081 {
			t.Fatalf("data plane still uses fallback: %+v", profile)
		}
	}
	unchanged := fetch()
	if !reflect.DeepEqual(unchanged.Applications, first.Applications) {
		t.Fatal("unchanged application catalog changed its published contents")
	}
	if err := store.Delete(context.Background(), "customer", "same-app"); err != nil {
		t.Fatal(err)
	}
	deleted := fetch()
	if deleted.Generation <= first.Generation {
		t.Fatal("deletion did not advance the bundle")
	}
	if _, ok, _ := edge.Get(context.Background(), "customer", "same-app"); ok {
		t.Fatal("deleted private app remained reachable")
	}
	if _, ok, _ := edge.Get(context.Background(), "other", "same-app"); !ok {
		t.Fatal("another tenant's app was removed")
	}
	if err := store.Delete(context.Background(), "other", "same-app"); err != nil {
		t.Fatal(err)
	}
	empty := fetch()
	if empty.Generation <= deleted.Generation || len(edge.Snapshot()) != 0 {
		t.Fatal("last deletion did not reach Edge")
	}
	// Restore both rows to test the tenant-facing authentication boundary.
	for _, tenant := range []string{"customer", "other"} {
		if _, err := store.Upsert(context.Background(), publishedAppForDistribution(tenant, "10.50.1.1"), tenant, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	source.token, source.tenantID = "token-customer", "customer"
	scoped, err := source.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if scoped.Applications == nil || scoped.Applications.Complete || len(scoped.Applications.Entries) != 1 || scoped.Applications.Entries["customer"] == nil {
		t.Fatalf("tenant received fleet authority: %+v", scoped.Applications)
	}
}

type unavailableApplicationCatalog struct {
	*appcatalog.Store
	fail bool
}

func (store *unavailableApplicationCatalog) ExportSnapshot(ctx context.Context) (map[string]map[string]appcatalog.Entry, error) {
	if store.fail {
		return nil, errors.New("database unavailable")
	}
	return store.Store.ExportSnapshot(ctx)
}

func TestApplicationBundleFailurePreservesVersionAndLocalCatalog(t *testing.T) {
	cp := &unavailableApplicationCatalog{Store: appcatalog.NewStore()}
	if _, err := cp.Upsert(context.Background(), publishedAppForDistribution("customer", "10.50.1.1"), "customer", time.Now()); err != nil {
		t.Fatal(err)
	}
	state := &applicationBundleState{}
	section, generation, err := state.read(context.Background(), cp)
	if err != nil {
		t.Fatal(err)
	}
	if _, same, err := state.read(context.Background(), cp); err != nil || same != generation {
		t.Fatalf("unchanged application catalog churned its generation: %d -> %d, %v", generation, same, err)
	}
	edge := appcatalog.NewStore()
	if err := applyApplicationBundle(edge, section); err != nil {
		t.Fatal(err)
	}
	cp.fail = true
	failed, next, err := state.read(context.Background(), cp)
	if err == nil || failed != nil || next != generation {
		t.Fatal("failed database read became a new/empty generation")
	}
	if err := applyApplicationBundle(edge, &applicationCatalogBundle{Complete: false}); err == nil {
		t.Fatal("incomplete snapshot accepted")
	}
	bad := publishedAppForDistribution("other", "10.50.1.1")
	if err := applyApplicationBundle(edge, &applicationCatalogBundle{Complete: true, Entries: map[string]map[string]appcatalog.Entry{"customer": {"same-app": bad}}}); err == nil {
		t.Fatal("cross-tenant entry accepted")
	}
	if entry, ok, _ := edge.Get(context.Background(), "customer", "same-app"); !ok || entry.TenantID != "customer" {
		t.Fatal("invalid snapshot changed the local catalog")
	}
	parent := filepath.Join(t.TempDir(), "missing-directory")
	if err := edge.SetStatePath(filepath.Join(parent, "state.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parent, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := applyApplicationBundle(edge, &applicationCatalogBundle{Complete: true}); err == nil {
		t.Fatal("persistence failure accepted")
	}
	if _, ok, _ := edge.Get(context.Background(), "customer", "same-app"); !ok {
		t.Fatal("failed persistence erased the live catalog")
	}
	source := configBundleSource{requireSigned: true}
	if _, err := source.apply(configBundlePayload{Applications: &applicationCatalogBundle{Complete: true}}, configApplyTargets{applications: edge}); err == nil {
		t.Fatal("unsigned snapshot accepted by a pinned source")
	}
}
