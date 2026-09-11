package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
)

// The material an agent installer must EMBED for one organization: the certificate authorities that
// organization's endpoints will trust, decided before the agent ever reaches a network.
//
// ★ WHY AT INSTALL TIME. Trust that arrives over the network has to be trusted before it arrives — the agent
// must already accept something in order to accept the document that tells it what to accept. Fixing the
// bundle in the installer removes that circle for the FIRST trust decision, and it makes a device's
// organization a property of the artifact it was installed from rather than of a runtime lookup: an endpoint
// built for one organization cannot be talked onto another's authorities.
//
// Replacing a CA stays a bundle operation rather than a re-install: the trust bundle holds LISTS and a
// monotonic serial, so an overlap carrying the old and new authority together is the normal state of a
// rotation, and devices report which they hold.
//
// This route is the source of truth for what to embed. It is deliberately ONE answer rather than three
// separate downloads: an installer assembled from parts fetched at different moments is how a package ends up
// pinning one organization's transport anchor beside another's interception root.
func registerTenantInstallBundleRoute(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, adminAuditOutbox adminAuditOutboxDeadReader) {
	mux.HandleFunc("GET /admin/tenant-install-bundle/{tenant}", adminEndpoint("admin.enrollment.read|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
		target := strings.TrimSpace(r.PathValue("tenant"))
		if target == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("tenant is required"))
			return
		}
		if err := adminTenantPKITargetAllowed(r, target, "reading the install material of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}

		// What the endpoint trusts to verify THE EDGE.
		//
		// ★★★ THIS READ THE SEED FLAG, NOT WHAT THE EDGE SERVES (2026-08-19, measured). config.TrustBundleCAPEM
		// is the value -trust-bundle-ca was started with; once the durable trust store exists it is
		// AUTHORITATIVE and the flag is only its seed. On the reference lab the two had drifted so far apart
		// that this endpoint was still handing out two certificates the Edge does not present — one of them
		// carrying this product's PRE-RENAME brand in its common name, which dates the drift — instead of the
		// anchor it does (Lantern DSSE Transport CA (MSSP) v2). A device installed from this bundle could not
		// verify the Edge it was installed to reach.
		//
		// The comment beside the served bundle says an installer and a fleet must never look at two different
		// documents for one organization. That promise was kept for the interception root and broken here, in
		// the one field an installer cannot recover from being wrong about.
		//
		// currentTrustAnchors is the same source the served bundle reads, so the two cannot drift again.
		transportAnchors, _ := currentTrustAnchors(config)
		transportAnchors = strings.TrimSpace(transportAnchors)
		// ★ And this organization's OWN anchor, when it has one (roadmap D, S2): the device is served that
		// certificate the moment its agent sends the organization's name, so an installer that embedded only
		// the shared set would produce a device that fails at exactly that point.
		if own, ok := transportTenantCertificates.AnchorFor(target); ok {
			transportAnchors = strings.TrimRight(transportAnchors, "\n") + "\n" + strings.TrimSpace(own)
		}

		// What the endpoint must hold to have its traffic inspected: THIS organization's interception root,
		// and no other's. Empty is a real and important answer, not a gap to paper over — it means this
		// organization has no issuer of its own yet, so its traffic is signed by the node-wide intermediate
		// (or, once per-tenant signing is in force, not intercepted at all).
		interceptionRootPEM, interceptionCN := "", ""
		if config.NetworkExtensionLabTLS != nil {
			for _, issuer := range config.NetworkExtensionLabTLS.ListOfflineTenantIntermediates() {
				if strings.EqualFold(strings.TrimSpace(issuer.Tenant), target) {
					interceptionRootPEM, interceptionCN = issuer.RootPEM, issuer.RootCommonName
				}
			}
		}
		ownIssuer := strings.TrimSpace(interceptionRootPEM) != ""
		// ★ THE FALLBACK IS WRONG AFTER A REVOCATION (2026-08-16, found live). An organization with no issuer
		// of its own is served by the node's anchor, so the fallback below is right — but a REVOKED
		// organization has no issuer for the opposite reason: this node has decided its traffic must not be
		// signed under any other authority. Falling back there hands its installer the deployment's root and
		// calls the bundle complete, which is the same defect the signing path had (an empty per-tenant set
		// read as "per-tenant is not in force") wearing the distribution path's clothes. Absent material,
		// reported as absent, is what lets an installer refuse.
		revocationReason, revoked := "", false
		if config.NetworkExtensionLabTLS != nil {
			revocationReason, revoked = config.NetworkExtensionLabTLS.TenantInterceptionRevoked(target)
		}
		if !ownIssuer && !revoked {
			// Fall back to the anchor this node signs under, which is what an organization without its own
			// issuer is really served by. Saying so explicitly below matters more than the value: an installer
			// that embedded this believing it was the organization's own would pin the operator's root into a
			// customer's fleet.
			interceptionRootPEM = string(config.NetworkExtensionLabTLS.RootCertificatePEM())
		}

		// ★★★ "NOTHING" AND "NOT MINE TO SAY" LOOKED IDENTICAL (2026-08-21, measured across both planes).
		// Everything above is read from THIS NODE's data plane: the anchors it serves, the interception engine
		// it runs. A control plane has neither — it holds the AUTHORITIES and serves no traffic — so the same
		// route, for the same organization, with the same credential, answered:
		//
		//   edge          complete=true  root="Lab Tenant Interception Root 2028"  transport_ca 1335 bytes
		//   control plane complete=false root=""                                   transport_ca 0 bytes
		//
		// The second is indistinguishable from a correctly-answered "this organization has nothing set up",
		// and this is the document an installer embeds — the Windows profile tool reads exactly this route for
		// the interception root. So the answer now NAMES what is absent and why, and says out loud when the
		// node it came from cannot serve this material at all. `complete` is still the field to gate on; what
		// changes is that a caller pointed at the wrong plane is told so instead of reading a plausible empty.
		missing := []string{}
		if transportAnchors == "" {
			missing = append(missing, "transport_ca_pem: this node serves no transport anchors, so it cannot "+
				"say what verifies the Edge. A node with none is either not configured yet or is a CONTROL "+
				"PLANE — this document describes what an EDGE presents, so ask one")
		}
		if strings.TrimSpace(interceptionRootPEM) == "" && !revoked {
			missing = append(missing, "interception_root_pem: this node runs no interception engine and this "+
				"organization has no offline issuer here, so there is no root for its endpoints to hold")
		}
		if revoked {
			missing = append(missing, "interception_root_pem: withheld — this organization's interception "+
				"authority was revoked here, and an installer must not be assembled while it is")
		}

		// ★★★ AND THE NAME THIS ORGANIZATION'S DEVICES MUST SEND (2026-08-22, measured — this route's own note
		// says "embed these in the agent installer for this organization", and it did not carry the one thing
		// that makes a device reach that organization).
		//
		// An installer built from this answer got the organization's CA and its trust bundle and NO NAME. The
		// device then dials the Edge by ADDRESS, is served the DEPLOYMENT-WIDE certificate — and refuses it,
		// because the only anchor it was given is its own organization's. That is not a corner case: it is
		// exactly the failure this deployment spent a day on, and it becomes permanent the moment the shared
		// anchor leaves that organization's bundle, which is the last step of roadmap D.
		//
		// It is also what has been holding the enrolment fold's data port open. The port stays "until every agent has been
		// given the name", and the product's own install path was not giving it.
		// ★ THE SAME ANSWER THE AGENT CONFIGURATION PUBLISHES, from the same function. A second resolver here
		// would be a second opinion about which name an organization's devices send, and the two would drift.
		organization := agentConfigOrganization(target)
		named := strings.TrimSpace(fmt.Sprint(organization["transport_server_name"])) != ""
		// ★ A BUNDLE WITH AN ANCHOR AND NO NAME IS NOT COMPLETE. Reported the same way as everything else
		// absent here, so an operator reads WHY rather than inferring it from a key that is not there.
		if transportAnchors != "" && !named {
			missing = append(missing, "organization: this node serves no name for that organization, so an "+
				"installer built from this answer would dial the Edge by address, be served the "+
				"deployment-wide certificate, and refuse it against the anchor above")
		}
		complete := transportAnchors != "" && strings.TrimSpace(interceptionRootPEM) != "" && !revoked && named
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_tenant_install_bundle.v1",
			"tenant_id":      target,
			// The three pieces an installer embeds, in one answer so they cannot be assembled from different
			// moments — see the note on this route.
			"transport_ca_pem":              transportAnchors,
			"interception_root_pem":         interceptionRootPEM,
			"interception_root_common_name": interceptionCN,
			// Whether that interception root is THIS organization's own. False means it is the deployment's
			// shared anchor: correct to embed today, and the thing to revisit the moment this organization
			// gets an issuer of its own, because its devices will then be shown a different CA.
			"interception_root_is_own": ownIssuer,
			// Present only when this organization's authority was revoked here. An installer must not be
			// assembled while it is set: there is no interception root to embed, and the reason is the thing
			// somebody needs in order to decide what to load instead.
			"interception_revoked":        revoked,
			"interception_revoked_reason": revocationReason,
			// What is absent and WHY, in the answer rather than left for a reader to infer from empty strings.
			// Empty when nothing is missing.
			"missing": missing,
			// The names this organization's devices present. Absent only when this node serves none for it,
			// and then `missing` says so and `complete` is false.
			"organization": organization,
			// The signed document the agent starts from, so its first serial comes from the installer rather
			// than from the first network fetch — the point of fixing this at install time. A device that
			// starts at serial N refuses anything at or below it, so a captured older bundle cannot walk it
			// back onto a withdrawn authority.
			"trust_bundle": func() any {
				if env, ok := installBundleEnvelope(config, target, evaluator.PolicyBundle.TenantID); ok {
					return env
				}
				return nil
			}(),
			// An installer must be able to refuse rather than ship an agent that trusts nothing. Absent
			// material is reported as such instead of being emitted as an empty string somebody embeds.
			"complete": complete,
			"note": func() string {
				if revoked {
					return "DO NOT build an installer from this. This organization's interception authority was " +
						"revoked on this node, so there is no interception root to embed and its traffic is not " +
						"being intercepted. Load a replacement issuer first."
				}
				return "Embed these in the agent installer for this organization. Replacing an authority later is a new trust bundle carrying old and new together, not a re-install."
			}(),
		})
	}))
}

// installBundleEnvelope returns the signed trust bundle an installer should embed for this organization. It
// goes through the same per-organization cache the device-facing endpoint uses, so an installer and a running
// device can never be looking at two different documents for the same organization.
func installBundleEnvelope(config serverConfig, tenant, nodeTenant string) (any, bool) {
	if installTrustBundleFor == nil {
		return nil, false
	}
	return installTrustBundleFor(tenant)
}

// installTrustBundleFor is set when the trust bundle is being served at all. A package-level seam for the same
// reason invalidateTrustBundles is one: the cache is owned by the route registration that serves devices, and
// this admin route is registered elsewhere.
var installTrustBundleFor func(tenant string) (any, bool)
