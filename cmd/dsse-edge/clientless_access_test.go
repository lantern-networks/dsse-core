package main

import (
	"testing"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
)

// the clientless authorization contract — IdP required, published+tenant-scoped, reduced-trust
// (managed-device-only excluded), group authorization.
func TestDecideClientlessAccess(t *testing.T) {
	published := []clientlessPublishedApp{
		{ApplicationID: "wiki", TenantID: "t1"},
		{ApplicationID: "payroll", TenantID: "t1", RequireManagedDevice: true},
		{ApplicationID: "hr", TenantID: "t1", AllowedGroups: []string{"hr-staff"}},
	}
	req := func(app string, auth bool, groups ...string) clientlessAccessRequest {
		return clientlessAccessRequest{TenantID: "t1", UserID: "u1", IdPAuthenticated: auth, UserGroups: groups, ApplicationID: app}
	}

	// No IdP login -> denied before anything is revealed.
	if o := decideClientlessAccess(req("wiki", false), published); o.Allow || o.ReasonCode != "clientless_idp_login_required" {
		t.Fatalf("no idp: %+v", o)
	}
	// Authenticated to a published app with no group constraint -> granted, reduced-trust tier.
	if o := decideClientlessAccess(req("wiki", true), published); !o.Allow || o.Tier != "reduced_trust" {
		t.Fatalf("published app should be granted: %+v", o)
	}
	// Unpublished app -> not_published.
	if o := decideClientlessAccess(req("unknown", true), published); o.Allow || o.ReasonCode != "clientless_app_not_published" {
		t.Fatalf("unpublished: %+v", o)
	}
	// Cross-tenant app (lookup is tenant-scoped) -> indistinguishable from not_published.
	cross := clientlessAccessRequest{TenantID: "t2", UserID: "u1", IdPAuthenticated: true, ApplicationID: "wiki"}
	if o := decideClientlessAccess(cross, published); o.Allow || o.ReasonCode != "clientless_app_not_published" {
		t.Fatalf("cross-tenant must not reach t1 app: %+v", o)
	}
	// Managed-device-only app -> reduced-trust clientless cannot reach it.
	if o := decideClientlessAccess(req("payroll", true), published); o.Allow || o.ReasonCode != "clientless_requires_managed_device" {
		t.Fatalf("managed-only: %+v", o)
	}
	// Group-restricted app: wrong group denied, right group granted.
	if o := decideClientlessAccess(req("hr", true, "eng"), published); o.Allow || o.ReasonCode != "clientless_user_not_authorized" {
		t.Fatalf("wrong group: %+v", o)
	}
	if o := decideClientlessAccess(req("hr", true, "hr-staff"), published); !o.Allow {
		t.Fatalf("right group should be granted: %+v", o)
	}
}

// only a private_app with status=active is publishable over the clientless front door; high
// sensitivity flags it managed-device-only.
func TestClientlessPublishedAppFromCatalogEntry(t *testing.T) {
	if app, ok := clientlessPublishedAppFromCatalogEntry(appcatalog.Entry{ApplicationID: "wiki", TenantID: "t1", ApplicationType: "private_app", Status: "active"}); !ok || app.RequireManagedDevice {
		t.Fatalf("active private_app should be published, not managed-only: app=%+v ok=%v", app, ok)
	}
	if app, ok := clientlessPublishedAppFromCatalogEntry(appcatalog.Entry{ApplicationID: "p", TenantID: "t1", ApplicationType: "private_app", Status: "active", ApplicationSensitivity: "high"}); !ok || !app.RequireManagedDevice {
		t.Fatalf("high-sensitivity private_app should be managed-only: %+v ok=%v", app, ok)
	}
	if _, ok := clientlessPublishedAppFromCatalogEntry(appcatalog.Entry{ApplicationID: "s", TenantID: "t1", ApplicationType: "saas", Status: "active"}); ok {
		t.Fatal("saas app is not publishable over the clientless front door")
	}
	if _, ok := clientlessPublishedAppFromCatalogEntry(appcatalog.Entry{ApplicationID: "w", TenantID: "t1", ApplicationType: "private_app", Status: "inactive"}); ok {
		t.Fatal("inactive app is not published")
	}
}
