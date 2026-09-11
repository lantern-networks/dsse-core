package main

import (
	"strings"

	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
)

// (re-scoped 2026-06-18, docs/agentless_clientless_access_design.md): clientless published-app
// access. An unmanaged/agentless user reaches a SPECIFIC published internal app via the browser front door
// (IdP login), through the existing connector publish model — no endpoint agent, no customer-network
// change, enforcement still at the Edge. Because there is no device agent there is no device posture, so
// clientless access is a REDUCED-TRUST tier: it may reach only apps that are (a) published behind a
// connector for the tenant and (b) not flagged managed-device-only. Identity is the IdP login at the front
// door — in production bound to the verified front-door session, NEVER client-claimed (the published-app
// binding + managed-device gate below hold regardless, so a forged identity still cannot exceed the
// reduced-trust published set).
//
// This file is the pure authorization contract; the production OIDC front-door SESSION (which sets
// IdPAuthenticated / UserID from a verified login and reverse-proxies the allowed flow) is the deferred
// real-environment piece, not the decision contract.

const clientlessTierReducedTrust = "reduced_trust"

type clientlessAccessRequest struct {
	TenantID         string
	UserID           string // from the IdP login (verified front-door session in production)
	IdPAuthenticated bool   // the front-door IdP login succeeded
	UserGroups       []string
	ApplicationID    string // the target published app
}

// clientlessPublishedApp is the authorization-relevant view of a published app (derived from the
// application catalog — see clientlessPublishedAppFromCatalogEntry).
type clientlessPublishedApp struct {
	ApplicationID        string
	TenantID             string
	RequireManagedDevice bool     // high-posture app: not reachable over reduced-trust clientless
	AllowedGroups        []string // empty => any authenticated user
}

type clientlessAccessOutcome struct {
	Allow      bool   `json:"allow"`
	ReasonCode string `json:"reason_code"`
	Tier       string `json:"tier"`
}

// decideClientlessAccess is the authorization contract. Order matters: an unauthenticated request is
// denied before any app is revealed; an unpublished/cross-tenant app is indistinguishable from "not found";
// the reduced-trust tier cannot reach managed-device-only apps; finally group authorization is applied.
func decideClientlessAccess(req clientlessAccessRequest, published []clientlessPublishedApp) clientlessAccessOutcome {
	if !req.IdPAuthenticated || strings.TrimSpace(req.UserID) == "" {
		return clientlessAccessOutcome{false, "clientless_idp_login_required", clientlessTierReducedTrust}
	}
	app, ok := findClientlessPublishedApp(published, req.TenantID, req.ApplicationID)
	if !ok {
		// Covers both an unpublished app and a cross-tenant app (the lookup is tenant-scoped) — the
		// clientless front door cannot reach a host that is not published behind a connector for the tenant.
		return clientlessAccessOutcome{false, "clientless_app_not_published", clientlessTierReducedTrust}
	}
	if app.RequireManagedDevice {
		return clientlessAccessOutcome{false, "clientless_requires_managed_device", clientlessTierReducedTrust}
	}
	if len(app.AllowedGroups) > 0 && !anyClientlessGroupMatches(app.AllowedGroups, req.UserGroups) {
		return clientlessAccessOutcome{false, "clientless_user_not_authorized", clientlessTierReducedTrust}
	}
	return clientlessAccessOutcome{true, "clientless_access_granted", clientlessTierReducedTrust}
}

func findClientlessPublishedApp(published []clientlessPublishedApp, tenantID, applicationID string) (clientlessPublishedApp, bool) {
	tenantID = strings.TrimSpace(tenantID)
	applicationID = strings.TrimSpace(applicationID)
	if tenantID == "" || applicationID == "" {
		return clientlessPublishedApp{}, false
	}
	for _, app := range published {
		if strings.TrimSpace(app.TenantID) == tenantID && strings.TrimSpace(app.ApplicationID) == applicationID {
			return app, true
		}
	}
	return clientlessPublishedApp{}, false
}

func anyClientlessGroupMatches(allowed, have []string) bool {
	for _, a := range allowed {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		for _, h := range have {
			if strings.TrimSpace(h) == a {
				return true
			}
		}
	}
	return false
}

// clientlessPublishedAppFromCatalogEntry maps an application-catalog entry to the clientless view, and
// reports whether it is publishable over the clientless front door at all. Only a private_app with
// status=active is "published behind a connector"; a SaaS entry or an inactive app is not. A high-sensitivity
// app is managed-device-only (reduced-trust clientless cannot reach it).
func clientlessPublishedAppFromCatalogEntry(e appcatalog.Entry) (clientlessPublishedApp, bool) {
	if e.ApplicationType != "private_app" || strings.ToLower(strings.TrimSpace(e.Status)) != "active" {
		return clientlessPublishedApp{}, false
	}
	return clientlessPublishedApp{
		ApplicationID:        e.ApplicationID,
		TenantID:             e.TenantID,
		RequireManagedDevice: strings.ToLower(strings.TrimSpace(e.ApplicationSensitivity)) == "high",
	}, true
}
