package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/grantstore"
)

// ★★★ THE CALL SITES (2026-09-02). A grant that is reported, published and never applied is the same defect
// as a section written and never published — and Go compiles every one of those without complaint.
func TestGrantsAreReportedPublishedAndApplied(t *testing.T) {
	for _, c := range []struct{ file, needs, why string }{
		{"main.go", "registerGrantReportRoute(",
			"the authority never receives what the fleet minted, so no Edge but the minting one holds a grant"},
		{"main.go", "grantCPReporter{",
			"a node never tells the authority what it minted"},
		{"admin_policy_routes.go", "grantBundleSection(",
			"the authority never puts the grants in the bundle, so no Edge can learn them"},
		{"config_bundle_sync.go", "applyGrantBundleSection(",
			"an Edge never applies them, so the bundle carries them and nothing reads them"},
	} {
		body, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatalf("read %s: %v", c.file, err)
		}
		if !strings.Contains(string(body), c.needs) {
			t.Errorf("%s does not call %s — %s", c.file, c.needs, c.why)
		}
	}
	// ★ AND THE REPORTER READS THE STORE PER REPORT. It is constructed hundreds of lines before the store
	// exists, so taking the pointer eagerly captures nil — a reporter that runs forever and reports nothing.
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "grants: theGrantStore.Load,") {
		t.Error("the grant reporter is given a store rather than a way to find one; at the point it is " +
			"constructed there is no store yet, so it would report nothing forever")
	}
}

// A union, because revocation MARKS rather than deletes: an absence from the authority's set means "not heard
// yet", which is exactly a grant minted here a second ago.
func TestApplyingTheAuthoritysGrantsDoesNotDeleteAFreshOne(t *testing.T) {
	now := time.Now().UTC()
	local := grantstore.NewStore()
	fresh := grantstore.Grant{
		GrantID: "g-local", TenantID: "t1", UserID: "u", IdPID: "idp",
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	if _, err := local.Mint(fresh, time.Hour, now); err != nil {
		t.Fatalf("mint: %v", err)
	}
	authority := &grantBundle{Complete: true, Grants: []grantstore.Grant{{
		GrantID: "g-other", TenantID: "t1", UserID: "v", IdPID: "idp",
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}}}
	if added, _, err := applyGrantBundleSection(local, authority, now); err != nil || added != 1 {
		t.Fatalf("added=%d, want 1", added)
	}
	if _, ok := local.Get("g-local"); !ok {
		t.Fatal("the grant this node minted a second ago was deleted by an authority that had not heard of " +
			"it yet — the ceremony that earned it would have to be repeated")
	}

	// A revocation authored on the authority DOES reach this node.
	revoked := fresh
	revoked.Revoked = true
	if _, updated, err := applyGrantBundleSection(local, &grantBundle{Complete: true,
		Grants: []grantstore.Grant{revoked}}, now); err != nil || updated != 1 {
		t.Fatalf("updated=%d, want 1", updated)
	}
	if local.Valid("g-local", now) {
		t.Error("a grant revoked on the authority is still honoured here")
	}

	// An expired grant is not carried forward.
	old := grantstore.Grant{GrantID: "g-old", TenantID: "t1", UserID: "w", IdPID: "idp",
		IssuedAt: now.Add(-2 * time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339)}
	if added, _, err := applyGrantBundleSection(local, &grantBundle{Complete: true,
		Grants: []grantstore.Grant{old}}, now); err != nil || added != 0 {
		t.Error("an expired grant was merged, so the set grows forever")
	}
}
