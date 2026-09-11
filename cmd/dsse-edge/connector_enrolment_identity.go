package main

import (
	"context"
	"strings"

	"github.com/lantern-networks/dsse-core/enroll"
)

// connector_enrolment_identity.go — how a connector gets the certificate it is required to present.
//
// ★★★ WHY THIS EXISTS (2026-08-23, measured on the lab). The Admin Console's "Add connector" prints a command,
// and that command could not bring a connector up. Measured end to end against the reference deployment with a
// fresh Site:
//
//	dsse-connector --token <…> --state-dir <…>
//	connector enrolled from token into site "install-probe" as conn-46926fdf27b0
//	connector transport TLS: connector identity certificate is mandatory outside dev mode (mTLS):
//	    set --connector-client-cert/--connector-client-key
//
// The enrolment SUCCEEDED and the connector then refused to start, because the Edge requires a certificate
// issued by the connector's own organization (connector_runtime.go) and nothing in the enrolment issued one.
// The Console papered over the gap by printing two placeholder lines — "<your connector certificate>" — which
// is an instruction to go and run a certificate authority by hand before the product will start.
//
// ★ THE ANSWER IS THE DOOR DEVICES ALREADY USE, not a new one. A connector needs exactly what a device needs:
// a key it generated, signed by its organization's device CA, recorded where an administrator can see and
// revoke it. So this is a third ELIGIBILITY MODE on POST /enroll rather than a second enrolment endpoint — it
// inherits the rate limiter, the suspended-organization refusal, the disabled-identity gate, the per-tenant
// signer and the ledger write, all of which a parallel endpoint would have had to grow its own copies of.
//
// ★ WHAT IT PROVES. A connector holds no per-device token and no person is present at its first start, so what
// it presents is its Site's one-time bootstrap secret — the same secret the very first register presents. The
// secret is checked against the named Site WITHIN the claimed organization, so a caller naming another
// organization's Site finds nothing to match and is refused: the organization is proven by the match, never
// taken from the request. Same rule as everywhere else here.
//
// ★ AND THE SECRET IS NOT SPENT BY ASKING. The connector needs it twice in the same first run — once here for
// its certificate, once at register — because it cannot register before it can present a certificate. The
// Site's hash is rotated by the operator issuing a new command, which is the granularity that was already true.

// connectorEligibilityMode is the value a connector puts in Eligibility.Mode. Spelled out rather than reused
// from "token" so a connector's bootstrap secret can never be tried as a device eligibility token, and so a
// refusal in the log says which kind of caller was turned away.
const connectorEligibilityMode = "connector"

// connectorEnrolmentEligibility answers whether this caller may be issued a connector identity, and under which
// organization. It returns ok=false for every other mode, so it can sit at the front of the eligibility chain.
//
// siteStore may be nil (a deployment with no Site store cannot have issued a bootstrap secret, so there is
// nothing a connector could present) — then no connector is ever eligible, which is the safe direction.
func connectorEnrolmentEligibility(ctx context.Context, siteStore adminSiteStore, nodeTenant string,
	req enroll.Request, logf func(string, ...interface{})) (tenant string, ok bool) {
	if strings.TrimSpace(req.Eligibility.Mode) != connectorEligibilityMode {
		return "", false
	}
	site := strings.TrimSpace(req.Eligibility.Site)
	claimed := strings.TrimSpace(req.Tenant)
	secret := strings.TrimSpace(req.Eligibility.Token)
	if site == "" || claimed == "" || secret == "" {
		if logf != nil {
			// Which FIELD was missing is safe to say — it is about the shape of the request, not about whether
			// any particular Site or secret exists.
			logf("enroll_refused mode=connector connector=%q reason=%q site_named=%t tenant_named=%t secret_present=%t",
				req.DeviceID, "a connector enrolment names its organization, its Site and its bootstrap secret",
				site != "", claimed != "", secret != "")
		}
		return "", false
	}
	if siteStore == nil {
		if logf != nil {
			logf("enroll_refused mode=connector connector=%q reason=%q", req.DeviceID,
				"this Edge holds no Site store, so no connector bootstrap secret can be checked")
		}
		return "", false
	}
	// ★ THE ORGANIZATION IS THE ONE THE SITE IS IN. The lookup is scoped to the claimed organization, so a
	// caller presenting a valid secret for tenant_b's Site while claiming tenant_a finds no Site and is
	// refused — it cannot borrow one organization's secret to be issued under another's authority.
	if !connectorRegistrationSiteBootstrapAuthorized(ctx, siteStore, site, claimed, secret) {
		if logf != nil {
			// One sentence for every failure — unknown Site, wrong organization, wrong secret, none issued —
			// because /enroll is unauthenticated and an accurate answer would be an oracle for which Sites
			// exist and which are awaiting a connector.
			logf("enroll_refused mode=connector connector=%q site=%q tenant=%q reason=%q", req.DeviceID, site,
				claimed, "the bootstrap secret is not this Site's")
		}
		return "", false
	}
	// ★ AND THIS NODE MUST HOLD THAT ORGANIZATION'S AUTHORITY. Signing under the node's own would hand the
	// connector a certificate naming it as somebody else's infrastructure, and the Edge would then refuse it at
	// register for exactly that reason — an issued-and-unusable identity, which is worse than a refusal here.
	// The node's OWN organization is signed by the signer this endpoint was built with, which is why it is
	// exempt here — the same exemption the per-device token branch makes, for the same reason.
	if !strings.EqualFold(claimed, strings.TrimSpace(nodeTenant)) && tenantDeviceIdentity.For(claimed) == nil {
		if logf != nil {
			logf("enroll_refused mode=connector connector=%q tenant=%q reason=%q", req.DeviceID, claimed,
				"this node holds no device-identity authority for that organization: either the control plane "+
					"has not given it one, or the organization issues its own certificates")
		}
		return "", false
	}
	if logf != nil {
		logf("enroll_eligibility_connector connector=%q site=%q tenant=%q", req.DeviceID, site, claimed)
	}
	return claimed, true
}

// connectorEnrolmentAttribution is what the ledger records for a connector, so an administrator reading the
// enrolled list sees infrastructure rather than wondering which employee's laptop this is.
func connectorEnrolmentAttribution(site string) string {
	return "enrolled as a connector for site " + strings.TrimSpace(site)
}
