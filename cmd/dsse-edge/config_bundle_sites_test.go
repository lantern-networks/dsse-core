package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func siteBundleStore(t *testing.T) adminSiteStore {
	t.Helper()
	return newDurableAdminSiteStore(t.TempDir() + "/sites.json")
}

func putSite(t *testing.T, store adminSiteStore, tenant, id, secretHash string) {
	t.Helper()
	if _, err := store.Upsert(context.Background(), adminSiteModel{
		TenantID: tenant, SiteID: id, Name: id, BootstrapSecretHash: secretHash,
	}, time.Now().UTC()); err != nil {
		t.Fatalf("seed %s/%s: %v", tenant, id, err)
	}
}

func siteIDs(t *testing.T, store adminSiteStore, tenant string) []string {
	t.Helper()
	got, err := store.List(context.Background(), tenant)
	if err != nil {
		t.Fatalf("list %s: %v", tenant, err)
	}
	out := make([]string, 0, len(got))
	for _, s := range got {
		out = append(out, s.SiteID)
	}
	return out
}

func listsSite(all []string, want string) bool {
	for _, s := range all {
		if s == want {
			return true
		}
	}
	return false
}

// The defect this exists for, both halves: a Site CREATED on the control plane must arrive, and a Site DELETED
// there must stop existing on the Edge that admits connectors.
func TestTheEdgesSiteCatalogBecomesTheControlPlanes(t *testing.T) {
	cp, edge := siteBundleStore(t), siteBundleStore(t)
	putSite(t, cp, "tenant_a", "new-site", connectorRuntimeSecretHash("a-secret"))
	putSite(t, edge, "tenant_a", "stale-site", connectorRuntimeSecretHash("an-older-secret"))

	section := siteBundleSection(context.Background(), cp, []string{"tenant_a"})
	if section == nil || !section.Complete {
		t.Fatal("a durable control-plane store did not publish a complete Site catalog")
	}
	applySiteBundleSection(context.Background(), edge, section, time.Now().UTC(), nil)

	got := siteIDs(t, edge, "tenant_a")
	if !listsSite(got, "new-site") {
		t.Fatalf("the Site created on the control plane never reached the Edge: %v", got)
	}
	if listsSite(got, "stale-site") {
		t.Fatalf("a Site the control plane does not have is still on the Edge — an operator deletes it in the "+
			"Console and the Edge goes on honouring its bootstrap secret: %v", got)
	}
}

// ★ THE HASH HAS TO RIDE, or the Edge holds a Site it cannot check anything against, which is the same as not
// holding it — and a connector presenting a correct secret would be refused.
func TestTheBootstrapSecretHashTravelsWithTheSite(t *testing.T) {
	cp, edge := siteBundleStore(t), siteBundleStore(t)
	wantHash := connectorRuntimeSecretHash("the-secret-an-operator-was-given")
	putSite(t, cp, "tenant_a", "site-1", wantHash)
	applySiteBundleSection(context.Background(), edge,
		siteBundleSection(context.Background(), cp, []string{"tenant_a"}), time.Now().UTC(), nil)

	got, ok, err := edge.Get(context.Background(), "tenant_a", "site-1")
	if err != nil || !ok {
		t.Fatalf("the Site did not arrive: %v", err)
	}
	if got.BootstrapSecretHash != wantHash {
		t.Fatalf("bootstrap hash arrived as %q: the Edge cannot authorise a connector for this Site",
			got.BootstrapSecretHash)
	}
}

// An organization the section never spoke about must be left entirely alone. Publishing two organizations is
// not a statement that a third has none.
func TestAnOrganizationTheSectionDidNotMentionIsUntouched(t *testing.T) {
	cp, edge := siteBundleStore(t), siteBundleStore(t)
	putSite(t, cp, "tenant_a", "site-a", "")
	putSite(t, edge, "tenant_b", "site-b", "")

	applySiteBundleSection(context.Background(), edge,
		siteBundleSection(context.Background(), cp, []string{"tenant_a"}), time.Now().UTC(), nil)

	if got := siteIDs(t, edge, "tenant_b"); !listsSite(got, "site-b") {
		t.Fatalf("another organization's Sites were removed by a section that never named it: %v", got)
	}
}

// Lockout-safe: an empty or incomplete section keeps what the Edge holds. An in-memory control plane that has
// just restarted is empty for a reason that is not "there are none", and applying that would take the
// bootstrap secret every waiting connector is about to present with it.
func TestAnEmptyOrIncompleteCatalogKeepsWhatTheEdgeHolds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		section *siteCatalogBundle
	}{
		// An empty catalogue that does NOT name this organization says nothing about it.
		{"empty and silent about it", &siteCatalogBundle{Sites: []adminSiteModel{}, Tenants: []string{"tenant_z"}, Complete: true}},
		{"incomplete", &siteCatalogBundle{Sites: []adminSiteModel{{TenantID: "tenant_a", SiteID: "other"}},
			Tenants: []string{"tenant_a"}, Complete: false}},
		{"absent", nil},
	} {
		edge := siteBundleStore(t)
		putSite(t, edge, "tenant_a", "site-a", "")
		applySiteBundleSection(context.Background(), edge, tc.section, time.Now().UTC(), nil)
		if got := siteIDs(t, edge, "tenant_a"); !listsSite(got, "site-a") {
			t.Fatalf("%s: the Edge's Sites were erased: %v", tc.name, got)
		}
	}
}

// A node with no Site store is not the Site authority and must not publish a section that looks like one.
func TestANodeWithNoSiteStorePublishesNothing(t *testing.T) {
	if section := siteBundleSection(context.Background(), nil, []string{"tenant_a"}); section != nil {
		t.Fatal("a node holding no Site store published a Site catalog")
	}
}

// An in-memory store says so, because a replace-all built from one that has just restarted erases the fleet.
func TestAVolatileStoreDoesNotClaimACompleteCatalog(t *testing.T) {
	if adminSiteStoreIsDurable(newDurableAdminSiteStore("")) {
		t.Fatal("an in-memory Site store reported itself durable: a restart would erase every Site on the fleet")
	}
	if !adminSiteStoreIsDurable(newDurableAdminSiteStore(t.TempDir() + "/s.json")) {
		t.Fatal("a file-backed Site store reported itself volatile, so its catalog would never be applied")
	}
}

// ★★★ THE TEST THAT WOULD HAVE SAVED AN HOUR. A section can be built correctly, published correctly, and
// never travel, because an Edge applies a bundle only when the aggregate generation is NEWER. Adding a Site
// changed the bundle's contents and not its version, so the section sat in every published bundle and no Edge
// ever pulled for it — measured on the lab before this existed.
//
// The store, not the route, because the route needs half of main() to construct; what has to be true is that
// a mutation is VISIBLE as a number the aggregate can add.
func TestChangingTheSiteCatalogChangesItsGeneration(t *testing.T) {
	store := newDurableAdminSiteStore(t.TempDir() + "/sites.json")
	carrier, ok := interface{}(store).(interface{ ConfigGeneration() uint64 })
	if !ok {
		t.Fatal("the Site store reports no generation, so nothing it holds can ever reach an Edge")
	}
	start := carrier.ConfigGeneration()

	putSite(t, store, "tenant_a", "site-1", "")
	afterCreate := carrier.ConfigGeneration()
	if afterCreate <= start {
		t.Fatalf("creating a Site left the generation at %d: the bundle's contents change and its version "+
			"does not, so no Edge re-pulls", afterCreate)
	}
	if err := store.Delete(context.Background(), "tenant_a", "site-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if afterDelete := carrier.ConfigGeneration(); afterDelete <= afterCreate {
		t.Fatalf("deleting a Site left the generation at %d: the deletion never propagates, and the Edge goes "+
			"on honouring its bootstrap secret", afterDelete)
	}
}

// ★ AND THE SUM ACTUALLY ADDS IT. The store having a number is not the same as the bundle using it — the
// generation is a sum written out by hand, and a store missing from that line contributes nothing however
// carefully it counts. Read from the source, because building the real one needs most of main().
func TestTheBundleGenerationSumIncludesTheSiteStore(t *testing.T) {
	src := readSourceFile(t, "admin_policy_routes.go")
	if !strings.Contains(src, "siteGen") {
		t.Fatal("the bundle's aggregate generation does not include the Site store: Sites would be published " +
			"in every bundle and applied by nobody")
	}
	// Matched loosely on purpose: the assertion is that siteGen is ADDED, not what sits next to it. Pinning the
	// neighbour made this fail the moment the posture's generation joined the same sum, which is a change that
	// makes the sum MORE correct — a test that fails on those is a test that gets deleted.
	if !strings.Contains(src, "+ siteGen") {
		t.Fatal("siteGen is computed but not added to the returned sum")
	}
}

// ★★ THE LAST SITE. Deleting a Site propagates only while at least one remains, unless "there are none" can be
// said — measured on the lab: the control plane went to zero Sites and the Edge kept the one it had, with its
// own /admin/sites the only way to remove it. A catalogue that NAMES the organization and carries no Sites for
// it is that statement.
func TestDeletingTheLastSiteOfAnOrganizationStillReaches(t *testing.T) {
	edge := siteBundleStore(t)
	putSite(t, edge, "tenant_a", "the-only-one", connectorRuntimeSecretHash("a-secret"))

	applySiteBundleSection(context.Background(), edge, &siteCatalogBundle{
		Sites: []adminSiteModel{}, Tenants: []string{"tenant_a"}, Complete: true,
	}, time.Now().UTC(), nil)

	if got := siteIDs(t, edge, "tenant_a"); len(got) != 0 {
		t.Fatalf("the organization's last Site survived the control plane deleting it: %v — an operator "+
			"removes it in the Console and the Edge goes on honouring its bootstrap secret", got)
	}
}

// And the publisher actually says which organizations it looked at, or the statement above can never be made.
func TestThePublishedCatalogueNamesTheOrganizationsItSpeaksFor(t *testing.T) {
	cp := siteBundleStore(t)
	putSite(t, cp, "tenant_a", "site-a", "")
	section := siteBundleSection(context.Background(), cp, []string{"tenant_a", "tenant_b"})
	if section == nil {
		t.Fatal("no section")
	}
	if !listsSite(section.Tenants, "tenant_a") || !listsSite(section.Tenants, "tenant_b") {
		t.Fatalf("the catalogue named %v: an organization it looked at and found empty must still be named, "+
			"or deleting its last Site never propagates", section.Tenants)
	}
}
