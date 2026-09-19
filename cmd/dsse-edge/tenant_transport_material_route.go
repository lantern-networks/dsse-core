package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// tenant_transport_material_route.go — the door an Edge fetches its per-organization transport material from.
//
// ★★★ IT HANDS OUT PRIVATE KEYS, SO READ THE THREE RULES BEFORE CHANGING ANYTHING HERE.
//
//  1. **The caller must be an Edge, proven the way every other Edge→control-plane route proves it**: the same
//     bearer AND a client certificate that chains to a registered tenant CA. A bearer alone is a shared
//     secret, and this route turns a shared secret into every organization's transport identity.
//  2. **What comes back expires.** The lifetime is the deployment's, not the caller's — an Edge cannot ask for
//     longer. A node that vanishes takes nothing durable with it.
//  3. **An organization with no authority here gets nothing.** Never a fallback, never the shared certificate:
//     silently handing back something generic is how a device ends up refusing the Edge it was steered to.
//
// Why it exists at all: the fleet is shared and autoscaled (decided 2026-08-20), and before this every
// per-organization certificate was a file a human had placed on a host. Measured on this repository's own
// scale-out definition: it carried none of them.
// materialGeneration is the one number an Edge compares against to decide whether to ask for material.
//
// ★★★ IT COVERED THE TRANSPORT AUTHORITIES ONLY, AND THE NEXT THING ADDED TO THIS RESPONSE WAS INVISIBLE
// (2026-08-21, measured within a minute of shipping it). Creating an organization's device-identity authority
// changed nothing an Edge could see: both nodes answered the cheap question with "unchanged" and installed
// "device identity for 0". The rule this repeats is the trust bundle's: the number has to follow EVERYTHING
// the answer contains, or a field added later reaches nobody.
func materialGeneration(transport *tenantTransportAuthority, interception *tenantInterceptionAuthority,
	deviceIdentity *tenantDeviceAuthority, registrations ...deviceCARegistrationSnapshot) uint64 {
	// ★★★ A FINGERPRINT OF WHAT THE AUTHORITIES ARE, NOT A COUNT OF HOW OFTEN THEY CHANGED (2026-08-22).
	// See material_generation_is_a_fingerprint.go: the counters reset on a control-plane restart, so the sum
	// walked back down and then re-reached a value an Edge was already holding — and that Edge was told
	// UNCHANGED for ever, while the rest of the fleet moved on.
	parts := []string{}
	if len(registrations) == 1 {
		parts = append(parts, fmt.Sprintf("device-registrations\x1f%d", registrations[0].fingerprint()))
	}
	if transport != nil {
		parts = append(parts, transport.GenerationParts()...)
	}
	if interception != nil {
		parts = append(parts, interception.GenerationParts()...)
	}
	if deviceIdentity != nil {
		parts = append(parts, deviceIdentity.GenerationParts()...)
	}
	return materialFingerprint(parts)
}

func registerTenantTransportMaterialRoute(mux *http.ServeMux, authority *tenantTransportAuthority,
	interception *tenantInterceptionAuthority, deviceIdentity *tenantDeviceAuthority, token string,
	ttl time.Duration, tenantCARegistry *tenantca.TenantCARegistry, devMode bool, distributors ...*tenantTrustDistributor) {
	token = strings.TrimSpace(token)
	if authority == nil || token == "" {
		return
	}
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	mux.HandleFunc("POST /tenant-edge-material", func(w http.ResponseWriter, r *http.Request) {
		if !auditIngestBearerValid(r, token) {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("tenant-edge-material: unauthorized"))
			return
		}
		// The same identification the audit path uses: WHICH Edge is this. A route that mints an
		// organization's server identity must not be reachable with a shared bearer alone.
		shipper, verified := auditIngestShipperFrom(r, tenantCARegistry)
		edge := strings.TrimSpace(shipper.Identity)
		if !verified && !devMode {
			writeError(w, http.StatusForbidden, fmt.Errorf("tenant-edge-material: this request presents no "+
				"Edge certificate, so the material could not be attributed to a node — refusing rather than "+
				"handing an organization's transport identity to an unidentified caller"))
			return
		}
		// ★★ AND "VERIFIED" IS NOT "AN EDGE" (2026-08-22). The check above is satisfied by ANY certificate the
		// listener accepts, and the refusal above says "Edge certificate" — a promise wider than what was being
		// enforced. This route hands out an organization's transport, interception and device-identity PRIVATE
		// KEYS; the one caller it exists for is an Edge, which carries an operator-issued certificate.
		//
		// A certificate that resolves to an ORGANIZATION through the tenant CA registry is, definitionally, not
		// that: it is a device or a connector, enrolled under a customer's own authority. auditIngestShipperFrom
		// already computes this and the answer was being discarded. Refusing on it costs a real Edge nothing —
		// its certificate chains to the operator anchors and resolves to no organization — and it holds even if
		// a deployment later widens -audit-ingest-client-ca to include tenant CAs, which is the configuration
		// that would otherwise turn one enrolled laptop into every organization's issuing key.
		if tenant := strings.TrimSpace(shipper.CertTenant); tenant != "" {
			logInfof("tenant_edge_material_refused_tenant_certificate identity=%q cert_tenant=%q", edge, tenant)
			writeError(w, http.StatusForbidden, fmt.Errorf("tenant-edge-material: this certificate was issued "+
				"by organization %q's own authority, which makes it a device or a connector and not an Edge of "+
				"this deployment; issuing material to it would hand that organization's signing keys to one of "+
				"the things they are meant to sign for", tenant))
			return
		}
		var body struct {
			Tenants []string `json:"tenants"`
			// KnownGeneration lets an Edge ask the cheap question — see where it is compared below.
			KnownGeneration uint64 `json:"known_generation,omitempty"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("tenant-edge-material: %w", err))
			return
		}
		// Read each authority once, before the unchanged check. A database error must not
		// certify a stale generation as current or be interpreted as an absent tenant.
		authority, err := authority.materialSnapshot()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		interception, err := interception.materialSnapshot()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		deviceIdentity, err := deviceIdentity.materialSnapshot()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		registrations, err := readDeviceCARegistrations(tenantCARegistry, tenantCARegistryShared)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}

		out := struct {
			TrustBundles map[string]tenantTrustDistribution `json:"trust_bundles"`
			Materials    []tenantTransportMaterial          `json:"materials"`
			Interception []tenantInterceptionMaterial       `json:"interception,omitempty"`
			// ★ THE THIRD THING AN EDGE NEEDS TO SERVE AN ORGANIZATION (2026-08-21): the authority its devices
			// are ENROLLED under. Without it an Edge can terminate that organization's transport and intercept
			// for it, and cannot admit a single new device — which is how an enrolment token issued by that
			// organization's own administrator came to be refused by every Edge in the fleet.
			DeviceIdentity []tenantDeviceMaterial `json:"device_identity,omitempty"`
			Refused        []string               `json:"refused,omitempty"`
			TTL            string                 `json:"ttl"`
			Generation     uint64                 `json:"generation,omitempty"`
			Unchanged      bool                   `json:"unchanged,omitempty"`
		}{TTL: ttl.String(), Generation: materialGeneration(authority, interception, deviceIdentity, registrations)}
		if len(distributors) == 1 && distributors[0] != nil {
			out.TrustBundles, err = distributors[0].Publish(authority, interception)
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, err)
				return
			}
		}

		// ★ CHEAP QUESTION, RARE ANSWER (2026-08-20). A rotation that nobody notices for eight hours is not a
		// rotation: Edges refresh material at two thirds of a twelve-hour life, so an act an operator performed
		// reached nobody until then — the incoming authority unannounced, no device asked to adopt it, and no
		// signal that anything was pending.
		//
		// So an Edge can ask often whether anything changed, and pay for material only when it has. Minting on
		// every poll would sign a certificate a minute per organization, which is why the answer is a number.
		if body.KnownGeneration > 0 && authority != nil &&
			out.Generation == body.KnownGeneration {
			out.Unchanged = true
			writeJSON(w, http.StatusOK, out)
			return
		}
		wanted := body.Tenants
		if len(wanted) == 0 {
			// ★ EMPTY MEANS "EVERYTHING YOU HOLD FOR ME", and that is the normal case in a shared fleet: every
			// Edge serves every organization, and a node that has just appeared cannot know the list — the
			// control plane is the one that knows. Asking the node to enumerate would make a new organization
			// invisible to every Edge that started before it.
			//
			// ★★★ AND "EVERYTHING" IS ALL THREE TIERS, NOT THE TRANSPORT ONE (2026-08-27, measured after
			// walking a customer's whole PKI through the Console). This list used to be
			// authority.Organizations() — the transport authority's alone — so an organization given an
			// interception root and no transport authority was in nobody's list. The Edge fetched
			// successfully, was handed nothing, and went on signing that customer's traffic under the
			// deployment's shared root while the control plane and the Console both showed the customer's own
			// root in force.
			//
			// The three tiers are set up on three separate screens and a customer is under no obligation to do
			// all three, so this is the ordinary path. Each tier still refuses on its own for an organization
			// it holds nothing for — which is what keeps "they run their own PKI" distinguishable from "they
			// were never asked about".
			wanted = organizationsThisControlPlaneHoldsAnythingFor(authority, interception, deviceIdentity)
		}
		for _, tenant := range wanted {
			// ★ EVERY AUTHORITY THIS ORGANIZATION IS BETWEEN, not just the one in force (2026-08-20). During a
			// rotation an organization has two, and an Edge that is handed only the current one can never
			// announce what its devices are being asked to move to — so the rotation would never finish, on
			// any node. The Edge decides which to SERVE; the control plane's job is to make sure it holds
			// both.
			mats, err := authority.IssueAllFor(tenant, edge, ttl)
			if err != nil && len(mats) == 0 {
				// Named, not silent: an Edge that is missing one organization needs to know WHICH, and the
				// fleet guard on the other side refuses to start rather than serving the wrong certificate.
				out.Refused = append(out.Refused, strings.TrimSpace(tenant)+": "+err.Error())
				continue
			}
			if err != nil {
				// It has what it needs to serve, and not what it needs to move. Both facts go back.
				out.Refused = append(out.Refused, strings.TrimSpace(tenant)+": "+err.Error())
			}
			out.Materials = append(out.Materials, mats...)
		}
		// ★ ONE FETCH FOR EVERYTHING AN EDGE NEEDS TO SERVE AN ORGANIZATION. Two routes would mean two
		// refresh cycles, two expiries and two ways for a node to be half-equipped — and a node that can
		// terminate an organization's transport but not intercept for it is a node that quietly stops
		// enforcing.
		if interception != nil {
			for _, tenant := range wanted {
				mat, err := interception.IssueFor(tenant, edge, ttl)
				if err != nil {
					out.Refused = append(out.Refused, "interception "+strings.TrimSpace(tenant)+": "+err.Error())
					continue
				}
				out.Interception = append(out.Interception, mat)
			}
		}
		if deviceIdentity != nil {
			for _, tenant := range wanted {
				mat, err := deviceIdentity.IssueFor(tenant, ttl)
				if err != nil {
					// An organization that runs its own PKI has no authority here and is not missing anything:
					// its devices are issued by a CA it holds and registered through /admin/tenant-cas. Named
					// anyway, because "this Edge cannot enrol for them" is a fact an operator should be able to
					// read rather than deduce.
					out.Refused = append(out.Refused, "device-identity "+strings.TrimSpace(tenant)+": "+err.Error())
					continue
				}
				mat.AdmissionCAPEM = deviceAdmissionAnchors(deviceIdentity.cas[strings.ToLower(strings.TrimSpace(tenant))], registrations)
				out.DeviceIdentity = append(out.DeviceIdentity, mat)
			}
		}
		log.Printf("tenant_edge_material issued to %q: transport for %d organization(s), interception for %d, "+
			"device identity for %d, refused %d, valid %s", edge, len(out.Materials), len(out.Interception),
			len(out.DeviceIdentity), len(out.Refused), ttl)
		writeJSON(w, http.StatusOK, out)
	})
	log.Printf("tenant transport material: this control plane issues per-organization server certificates to "+
		"Edges on request, valid %s (an Edge that appears under load assembles itself; nothing long-lived is "+
		"placed on it)", ttl)
}

// registerTenantTransportAuthorityAdminRoute is how an organization's transport authority comes into being.
//
// ★ CREATING IT IS AN ACT, NOT A SIDE EFFECT. An authority minted automatically — on an Edge's request, or on
// first sight of an organization — would be an anchor nobody chose, for a name nobody chose, that every one of
// that organization's devices must then adopt. So it is asked for, by the organization (or by the operator
// through the envelope, like every other cross-organization PKI act), and the NAME is given at that moment
// because the name and the certificate have to stay together.
//
// Idempotent: asking again returns the authority that exists rather than replacing it. Replacing it is a
// rotation, which is roadmap D's add-measure-withdraw and not a side effect of a second POST.
// ★ REGISTERED WHETHER OR NOT THIS NODE HOLDS AUTHORITIES (2026-08-20). Conditional registration made the
// elevated-act rule INERT: the act sat on the list that says "an operator needs a time-boxed elevation for
// this", and on a node without the store no route served it, so the rule matched nothing. A rule everybody
// believes is in force and nothing enforces is the shape this repository keeps paying for. The route now
// exists everywhere and says plainly when this node cannot act.
func registerTenantTransportAuthorityAdminRoute(mux *http.ServeMux,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, authority *tenantTransportAuthority) {
	// The same rights the sibling PKI act needs: an organization's own administrator may do this for their own
	// organization, and an operator crossing into another goes through the envelope below. Inventing a new
	// permission name would have made the act unreachable for everyone until somebody granted it.
	mux.HandleFunc("POST /admin/tenant-transport-authority", adminEndpoint("admin.enrollment.write|admin.tenant.admin",
		func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				TenantID   string `json:"tenant_id"`
				ServerName string `json:"server_name"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			tenant, terr := adminTenantForWrite(r, body.TenantID)
			if terr != nil {
				writeError(w, http.StatusForbidden, terr)
				return
			}
			if err := adminTenantPKITargetAllowed(r, tenant, "creating a transport authority for"); err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}
			if authority == nil {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("this control plane holds no transport "+
					"authorities (-tenant-transport-authority-store is not set), so it can create none. Edges "+
					"here read per-organization certificates from files instead"))
				return
			}
			// ★ A NAME NOBODY HAD TO INVENT (2026-08-21). A minted organization id protects nothing if the
			// transport name is still typed in by hand as "northwind.dsse.invalid" — the SNI oracle reads the
			// NAME. So an omitted name is derived from the id, and giving one explicitly stays possible for an
			// organization that wants its own domain on its own certificate: then it is their decision, made
			// deliberately, rather than one a form made for them.
			serverName := strings.TrimSpace(body.ServerName)
			if serverName == "" {
				serverName = organizationTransportServerName(tenant, deploymentNameSuffix())
			}
			row, err := authority.EnsureCA(tenant, serverName)
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"tenant_id":   row.TenantID,
				"server_name": row.ServerName,
				"anchor_pem":  row.CACertPEM,
				"created_at":  row.CreatedAt,
				"applies_to": "every Edge in the fleet, as each one next fetches its material — this organization's " +
					"devices verify their Edge with the anchor above",
			})
		}))
}

// registerTenantTransportRotationAdminRoutes are the two acts a rotation is made of.
//
// ★★★ THE MACHINERY EXISTED AND NOTHING STARTED IT (2026-08-20). Announce-alongside, promote-on-evidence and
// withdraw-the-previous were built, proven on the lab and complete — and the only way to give an organization
// a different authority was to destroy the one it had and create another. That is the order that stranded a
// device this morning for thirty-one minutes, and no operator should be asked to perform it.
//
// Two acts, because they are two decisions with different evidence behind them:
//
//	rotate  — add a second authority. Additive: nothing stops being served, nothing stops being trusted, and
//	          every Edge starts announcing the new one alongside the old.
//	retire  — end the rotation. Destructive: the previous authority stops existing, and any Edge that has not
//	          yet promoted loses what it was serving. The Edges decide when to START serving on their own
//	          evidence about devices; only an operator can decide the previous one is finished.
func registerTenantTransportRotationAdminRoutes(mux *http.ServeMux,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, authority *tenantTransportAuthority,
	configSourceURL string, gates ...pkiTransitionAdmission) {
	// ★ ONE HANDLER PER LITERAL ROUTE, WITH ITS GUARDS INLINE (2026-08-20, after two source-scanning tools read
	// this wrong in a row). A shared closure that registers several paths defeats them both: the route manifest
	// could not resolve a path held in a variable, and the generator that lists control-plane-authored writes
	// attributes a guard to whatever HandleFunc line came before it — which was a DIFFERENT route. The
	// convention here is what the tools read, and being clever with it costs more than the duplication saves.
	body := func(w http.ResponseWriter, r *http.Request,
		do func(*tenantTransportAuthority, string) (*storedTenantTransportCA, error), what string) {
		var in struct {
			TenantID string `json:"tenant_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant, terr := adminTenantForWrite(r, in.TenantID)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		if err := adminTenantPKITargetAllowed(r, tenant, what+" the transport authority of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		if authority == nil {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("this control plane holds no transport "+
				"authorities (-tenant-transport-authority-store is not set)"))
			return
		}
		row, err := do(authority, tenant)
		if err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_tenant_transport_rotation.v1",
			"tenant_id":      tenant,
			"server_name":    row.ServerName,
			"anchor_pem":     row.CACertPEM,
			"created_at":     row.CreatedAt,
			"applies_to": "every Edge in the fleet, on its next material fetch. They announce it beside " +
				"the authority in force and only start serving it once this organization's devices have " +
				"been measured holding it.",
		})
	}

	// The read the screen asks before it offers either act — see StateFor.
	mux.HandleFunc("GET /admin/tenant-transport-authority", adminEndpoint("admin.certs.read|admin.tenant.admin",
		func(w http.ResponseWriter, r *http.Request) {
			tenant := strings.TrimSpace(adminTenantIDFromRequest(r))
			if tenant == "" {
				writeError(w, http.StatusForbidden, fmt.Errorf("this request names no organization"))
				return
			}
			if err := adminTenantPKITargetAllowed(r, tenant, "reading the transport authority of"); err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}
			// ★★ A NODE THAT HOLDS NO AUTHORITIES ANSWERED "THIS ORGANIZATION HAS NONE" (2026-08-21, measured
			// across both planes). These authorities live on a CONTROL PLANE; an Edge holds none by design and
			// answered has_authority:false for organizations that have one:
			//
			//	control plane  has_authority=true   server_name=lab.dsse.invalid
			//	edge           has_authority=false  server_name=""
			//
			// The Console asks the control plane, so no screen was wrong — the ROUTE was, and an answer that
			// depends on which node replied is the shape this repository keeps finding. Same correction as the
			// install bundle: "not mine to say" is a different answer from "there is none".
			if authority == nil {
				writeError(w, http.StatusConflict, fmt.Errorf(
					"this node holds no per-organization transport authorities, so it cannot say whether %q has "+
						"one — that is a CONTROL PLANE's answer, and answering it from here would report every "+
						"organization as having none. Ask the control plane", tenant))
				return
			}
			name, inForce, incoming, rotating, known := authority.StateFor(tenant)
			previousName, renamedAt := authority.RenameInFlight(tenant)
			answer := map[string]any{
				"schema_version": "admin_tenant_transport_authority.v1",
				"tenant_id":      tenant,
				"has_authority":  known,
				"server_name":    name,
				"in_force_since": inForce,
				"rotating":       rotating,
				"incoming_since": incoming,
				// The OTHER movement this authority can be in. Both are always present, so a screen never has to
				// infer "no rename" from a missing key.
				"renaming":             previousName != "",
				"previous_server_name": previousName,
				"renamed_at":           renamedAt,
			}
			// The certificate itself, in the same shape the other two authorities report theirs — see Row.
			// Without it the Console can offer to replace this authority and cannot say what it is replacing.
			if row, held := authority.Row(tenant); held && row != nil {
				if summary, ok := summarizeCertificatePEM(row.CACertPEM); ok {
					answer["signing"] = summary
				}
				if row.Incoming != nil {
					if summary, ok := summarizeCertificatePEM(row.Incoming.CACertPEM); ok {
						answer["incoming"] = summary
					}
				}
			}
			// ★ AND WHY IT HAS NONE, in the same words its two siblings use (2026-08-22). "has_authority:
			// false" is a fact with no next step; an organization on the deployment's shared certificate is a
			// state somebody chose and can leave.
			if !known {
				answer["note"] = "This organization is served the deployment's own transport certificate. " +
					"Give it an authority of its own before its devices can verify this deployment on " +
					"nothing but their own organization's anchor."
			}
			if previousName != "" {
				answer["rename_note"] = "This organization's certificate carries both names. Devices still " +
					"sending " + previousName + " keep working; ask an Edge (GET /admin/transport-name-rename) " +
					"which have moved before retiring it, or abandon the rename to go back to it."
			}
			writeJSON(w, http.StatusOK, answer)
		}))

	mux.HandleFunc("POST /admin/tenant-transport-authority/rotate",
		adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
			if configWriteRejectedWhenSourced(w, configSourceURL, "transport authority rotation") {
				return
			}
			body(w, r, func(a *tenantTransportAuthority, t string) (*storedTenantTransportCA, error) {
				return a.RotateCA(t)
			}, "rotating")
		}))

	// ★★★ MOVING AN ORGANIZATION OFF A NAME THAT NAMES IT (2026-08-22). See
	// transport_name_rename_readiness.go: an organization created before ids were issued is served under the
	// customer's own word, in plaintext SNI, on a deployment that strips ECH.
	mux.HandleFunc("POST /admin/tenant-transport-authority/rename",
		adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
			if configWriteRejectedWhenSourced(w, configSourceURL, "transport authority rename") {
				return
			}
			var req struct {
				TenantID   string `json:"tenant_id"`
				ServerName string `json:"server_name"`
			}
			_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req)
			tenant, terr := adminTenantForWrite(r, req.TenantID)
			if terr != nil {
				writeError(w, http.StatusForbidden, terr)
				return
			}
			if err := adminTenantPKITargetAllowed(r, tenant, "renaming the transport name of"); err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}
			if authority == nil {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("this control plane holds no transport authorities"))
				return
			}
			row, err := authority.RenameServerName(tenant, req.ServerName)
			if err != nil {
				writeError(w, http.StatusConflict, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"tenant_id": row.TenantID, "server_name": row.ServerName,
				"previous_server_name": row.PreviousServerName, "renamed_at": row.RenamedAt,
				"note": "The certificate now carries BOTH names, and both folded paths for each. Devices adopt " +
					"the new one from their trust bundle. Read GET /admin/transport-name-rename on each Edge " +
					"and retire the previous name only once every device reports sending the new one — " +
					"dropping it early is a TLS failure for the rest.",
			})
		}))

	mux.HandleFunc("POST /admin/tenant-transport-authority/abandon-rotation",
		adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
			if configWriteRejectedWhenSourced(w, configSourceURL, "transport authority rotation") {
				return
			}
			var req struct {
				TenantID string `json:"tenant_id"`
			}
			_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req)
			tenant, terr := adminTenantForWrite(r, req.TenantID)
			if terr != nil {
				writeError(w, http.StatusForbidden, terr)
				return
			}
			if err := adminTenantPKITargetAllowed(r, tenant, "abandoning the transport rotation of"); err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}
			if authority == nil {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("this control plane holds no transport authorities"))
				return
			}
			row, err := authority.admitTransition(tenant, "abandon-rotation", gates, func(candidate *tenantTransportAuthority, tenant string) (*storedTenantTransportCA, error) {
				return candidate.AbandonRotation(tenant)
			})
			if err != nil {
				writeError(w, http.StatusConflict, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"tenant_id": row.TenantID, "server_name": row.ServerName, "rotating": false,
				"note": "The incoming authority has been withdrawn after verifying every configured region serves the retained authority and every enabled device reports trusting it.",
			})
		}))

	mux.HandleFunc("POST /admin/tenant-transport-authority/abandon-rename",
		adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
			if configWriteRejectedWhenSourced(w, configSourceURL, "transport authority rename") {
				return
			}
			var req struct {
				TenantID string `json:"tenant_id"`
			}
			_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req)
			tenant, terr := adminTenantForWrite(r, req.TenantID)
			if terr != nil {
				writeError(w, http.StatusForbidden, terr)
				return
			}
			if err := adminTenantPKITargetAllowed(r, tenant, "abandoning the rename of"); err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}
			if authority == nil {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("this control plane holds no transport authorities"))
				return
			}
			row, err := authority.AbandonRename(tenant)
			if err != nil {
				writeError(w, http.StatusConflict, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"tenant_id": row.TenantID, "server_name": row.ServerName,
				"previous_server_name": row.PreviousServerName,
				"note": "The rename now runs the other way: this organization is back on " + row.ServerName +
					", and the certificate still carries " + row.PreviousServerName + " so devices that " +
					"already adopted it keep connecting while they move back. Nothing was dropped. Retire " +
					row.PreviousServerName + " only once GET /admin/transport-name-rename on an Edge says " +
					"every device has moved.",
			})
		}))

	mux.HandleFunc("POST /admin/tenant-transport-authority/retire-previous-name",
		adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
			if configWriteRejectedWhenSourced(w, configSourceURL, "transport authority rename") {
				return
			}
			var req struct {
				TenantID string `json:"tenant_id"`
			}
			_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req)
			tenant, terr := adminTenantForWrite(r, req.TenantID)
			if terr != nil {
				writeError(w, http.StatusForbidden, terr)
				return
			}
			if err := adminTenantPKITargetAllowed(r, tenant, "retiring the previous transport name of"); err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}
			if authority == nil {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("this control plane holds no transport authorities"))
				return
			}
			row, err := authority.RetirePreviousServerName(tenant)
			if err != nil {
				writeError(w, http.StatusConflict, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"tenant_id": row.TenantID, "server_name": row.ServerName, "previous_server_name": "",
			})
		}))

	mux.HandleFunc("POST /admin/tenant-transport-authority/retire-previous",
		adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
			if configWriteRejectedWhenSourced(w, configSourceURL, "transport authority rotation") {
				return
			}
			body(w, r, func(a *tenantTransportAuthority, t string) (*storedTenantTransportCA, error) {
				return a.admitTransition(t, "retire-previous", gates, func(candidate *tenantTransportAuthority, tenant string) (*storedTenantTransportCA, error) {
					return candidate.RetirePrevious(tenant)
				})
			}, "retiring the previous")
		}))
}

// registerTenantInterceptionAuthorityAdminRoute is how an organization hands the operator the right to
// intercept on its behalf.
//
// ★ IT IS AN IMPORT, NOT A CREATION, and that is the whole ownership line. The root an organization's devices
// trust stays with the organization; what arrives here is an issuing authority THEY signed under it, which
// this control plane then uses to mint a short-lived tier for each Edge. Creating a root here would mean
// asking every device to trust something the operator made.
func registerTenantInterceptionAuthorityAdminRoute(mux *http.ServeMux,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, authority *tenantInterceptionAuthority,
	tenantModels adminTenantModelRuntimeStore, audit func(*http.Request, string, string, *storedTenantInterceptionIssuer), gates ...pkiTransitionAdmission) {
	mux.HandleFunc("POST /admin/tenant-interception-authority", adminEndpoint("admin.enrollment.write|admin.tenant.admin",
		func(w http.ResponseWriter, r *http.Request) {
			var body struct {
				TenantID       string `json:"tenant_id"`
				RootPEM        string `json:"root_pem"`
				IssuingCertPEM string `json:"issuing_cert_pem"`
				IssuingKeyPEM  string `json:"issuing_key_pem"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&body); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			tenant, terr := adminTenantForWrite(r, body.TenantID)
			if terr != nil {
				writeError(w, http.StatusForbidden, terr)
				return
			}
			if err := adminTenantPKITargetAllowed(r, tenant, "delegating interception for"); err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}
			if authority == nil {
				writeError(w, http.StatusNotImplemented, fmt.Errorf("this control plane accepts no delegated "+
					"interception authorities (-tenant-interception-authority-store is not set)"))
				return
			}
			// ★★★ AN ORGANIZATION THAT DOES NOT BRING A PKI HAD NO ROUTE AT ALL (2026-08-30). This endpoint is
			// written for a customer who HAS one: they sign an issuing CA under their own root and hand over
			// the three PEMs. That is the right shape and it is not everyone's — an organization without a CA
			// team, which is the ordinary onboarding case and every lab, could not get an interception
			// authority here. The only thing in the product that minted one was the per-Edge route, which is
			// per-Edge by construction: a region ended up with one root per Edge process, all different, and
			// which one signed a device's traffic depended on which process the door picked.
			//
			// So: sending nothing means "make one for this organization". It goes through Import like any
			// other, so there is one set of checks and one shape in the store.
			minted := false
			rootPEM, issuingPEM, issuingKeyPEM := body.RootPEM, body.IssuingCertPEM, body.IssuingKeyPEM
			if strings.TrimSpace(rootPEM) == "" && strings.TrimSpace(issuingPEM) == "" &&
				strings.TrimSpace(issuingKeyPEM) == "" {
				// ★ AND NEVER OVER AN AUTHORITY THAT EXISTS. Minting a second one is a REPLACEMENT — staged,
				// announced, promoted only once every device holds the incoming root — and nobody asks for
				// that by leaving a body empty. An organization that already has one is told it has one.
				if authority.Has(tenant) {
					writeError(w, http.StatusConflict, fmt.Errorf("%q already has an interception authority. "+
						"Send a root, issuing certificate and key to REPLACE it — a replacement is staged and "+
						"promoted deliberately, because every device that has not adopted the incoming root "+
						"loses every HTTPS site the moment the fleet signs under it", tenant))
					return
				}
				name := tenant
				if tenantModels != nil {
					if model, err := tenantModels.Get(r.Context(), tenant); err == nil &&
						strings.TrimSpace(model.DisplayName) != "" {
						name = strings.TrimSpace(model.DisplayName)
					}
				}
				var mintErr error
				rootPEM, issuingPEM, issuingKeyPEM, mintErr = mintTenantInterceptionAuthority(tenant, name, time.Now())
				if mintErr != nil {
					writeError(w, http.StatusInternalServerError, mintErr)
					return
				}
				minted = true
				log.Printf("tenant_interception_authority MINTED for %q as %q — this deployment now holds the "+
					"authority its Edges sign that organization's traffic under, and every Edge takes the same "+
					"one", tenant, name)
			}
			row, err := authority.Import(tenant, rootPEM, issuingPEM, issuingKeyPEM)
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			// ★★ THE ANSWER SAYS WHICH OF THE TWO THINGS JUST HAPPENED (2026-08-22). A first authority takes
			// effect immediately; a REPLACEMENT is staged and nothing signs under it until it is promoted. An
			// answer that read the same for both is how somebody hands over a replacement, sees "applies to
			// every Edge", and believes the switch has happened.
			staged := authority.IsStaged(tenant)
			if audit != nil {
				action := "interception_authority_imported"
				if staged {
					action = "interception_authority_staged"
				}
				audit(r, row.TenantID, action, row)
			}
			applies := "every Edge in the fleet, as each one next fetches its material — this organization's " +
				"devices keep trusting the same root, so nothing on a device changes"
			if staged {
				applies = "nothing yet. This is a REPLACEMENT, so it is staged: every Edge will ANNOUNCE its " +
					"root so devices adopt it, and will go on signing under the authority in force. Read " +
					"GET /admin/interception-authority-rotation on each Edge, and promote only once every " +
					"device reports holding it — promoting early takes every HTTPS site away from the ones " +
					"that do not."
			}
			out := map[string]any{
				"tenant_id":   row.TenantID,
				"imported_at": row.ImportedAt,
				"staged":      staged,
				"applies_to":  applies,
				"minted":      minted,
			}
			// The root is what an operator has to get onto devices, and it is the only part of this they can
			// safely be handed. Returned on a mint because otherwise the one thing they need is the one thing
			// they would have to go and find.
			if minted {
				out["root_pem"] = row.RootPEM
				out["distribute"] = "this organization's devices must trust root_pem. Until one does, its " +
					"traffic is intercepted under a root it does not hold and every HTTPS site fails on it."
			}
			writeJSON(w, http.StatusOK, out)
		}))

	// ★★★ THE TWO ACTS A STAGED AUTHORITY NEEDS. Promoting is the switch — the dangerous half here, because
	// every device that has not adopted the incoming root loses every HTTPS site the moment the fleet signs
	// under it. Withdrawing is the way back, which matters as much: without it a staged authority that turns
	// out to be wrong could only be got rid of by promoting it.
	interceptionAct := func(w http.ResponseWriter, r *http.Request, what string,
		do func(*tenantInterceptionAuthority, string) (*storedTenantInterceptionIssuer, error)) {
		var body struct {
			TenantID string `json:"tenant_id"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body)
		tenant, terr := adminTenantForWrite(r, body.TenantID)
		if terr != nil {
			writeError(w, http.StatusForbidden, terr)
			return
		}
		if err := adminTenantPKITargetAllowed(r, tenant, what+" the interception authority of"); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}
		if authority == nil {
			writeError(w, http.StatusNotImplemented, fmt.Errorf("this control plane accepts no delegated "+
				"interception authorities, so there is none to %s", what))
			return
		}
		row, err := do(authority, tenant)
		if err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":   row.TenantID,
			"imported_at": row.ImportedAt,
			"staged":      row.Incoming != nil,
		})
	}

	mux.HandleFunc("POST /admin/tenant-interception-authority/promote",
		adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
			interceptionAct(w, r, "promoting", func(a *tenantInterceptionAuthority, t string) (*storedTenantInterceptionIssuer, error) {
				return a.admitTransition(t, "promote", gates, func(candidate *tenantInterceptionAuthority, tenant string) (*storedTenantInterceptionIssuer, error) {
					return candidate.Promote(tenant)
				})
			})
		}))

	mux.HandleFunc("POST /admin/tenant-interception-authority/withdraw-incoming",
		adminEndpoint("admin.enrollment.write|admin.tenant.admin", func(w http.ResponseWriter, r *http.Request) {
			interceptionAct(w, r, "withdrawing the staged authority of", func(a *tenantInterceptionAuthority, t string) (*storedTenantInterceptionIssuer, error) {
				return a.admitTransition(t, "withdraw-incoming", gates, func(candidate *tenantInterceptionAuthority, tenant string) (*storedTenantInterceptionIssuer, error) {
					return candidate.WithdrawIncoming(tenant)
				})
			})
		}))
}

// registerEnrolmentReportRoute is the MACHINE door for "a device enrolled here, into this organization".
//
// ★★★ THE FACT COULD NOT BE REPORTED ACROSS ORGANIZATIONS (2026-08-21, measured on the first cross-organization
// enrolment this deployment ever completed). The Edge reported it to the admin route with an operator bearer
// and X-Operate-Tenant, and the control plane answered 403: crossing into another organization needs a
// time-boxed elevation, and a machine holds none. The durable outbox did its job and queued it, forever.
//
// Two correct rules collided. An operator acting on a customer must be elevated; an Edge recording where a
// device actually enrolled is not an operator acting on anybody — it is the enforcement plane writing down a
// fact the ORGANIZATION'S OWN administrator authorised when they minted the enrolment token. Requiring a human
// elevation for a machine's factual report is how the report never happens, and the control plane is the
// authority for this ledger: an enrolment it never hears about is dropped from the Edge at the next config
// bundle, which is the "enrolled here and erased there" shape this deployment has already paid for once.
//
// So it gets its own door, on the channel where the Edge PROVES which node it is — the same certificate the
// material fetch presents — instead of a shared bearer. It can only enrol; it cannot disable, re-group or
// remove, and the ledger call it makes is the one that refuses to move a device that already belongs to
// somebody else.
// registerConnectorReportRoute receives the registration of a connector that joined at an Edge.
//
// ★★★ A CONNECTOR REACHES ONLY AN EDGE, SO THE AUTHORITY ONLY LEARNS BY BEING TOLD (2026-08-24, measured).
// There is no POST /admin/connectors — a connector is not created by an operator, it self-registers, and the
// operator then names it and gives it routes, both of which are writes the Console sends to the CONTROL
// PLANE. Without this door the authority has nothing to name and nothing to attach a route to, and cannot
// even delete a connector that is plainly running.
//
// Same door and same proof as the enrolment report beside it: the Edge presents the certificate the audit
// channel uses, so a shared bearer alone cannot write another organization's connector list. And the same
// rule — this RECORDS a registration the Edge already admitted with the Site's bootstrap secret. It does not
// re-decide it.
func registerConnectorReportRoute(mux *http.ServeMux, registry connectorRegistryStore,
	tenantCARegistry *tenantca.TenantCARegistry, configSourceURL string, devMode bool) {
	if registry == nil {
		return
	}
	// A node that PULLS its configuration is not the authority for this registry and must not write it — the
	// same rule the enrolment report states.
	if strings.TrimSpace(configSourceURL) != "" {
		return
	}
	mux.HandleFunc("POST /connector-report", func(w http.ResponseWriter, r *http.Request) {
		shipper, verified := auditIngestShipperFrom(r, tenantCARegistry)
		if !verified && !devMode {
			writeError(w, http.StatusForbidden, fmt.Errorf("connector-report: this request presents no Edge "+
				"certificate, so the registration could not be attributed to a node"))
			return
		}
		var body struct {
			Registration model.ConnectorRegistration `json:"registration"`
			TenantID     string                      `json:"tenant_id"`
			// AttachedRegionID marks an ATTACHMENT report: a node saying where this connector's tunnel is
			// terminating NOW, which is not what the connector declared when it enrolled.
			AttachedRegionID string `json:"attached_region_id,omitempty"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("connector-report: %w", err))
			return
		}
		reg := body.Registration
		if strings.TrimSpace(reg.ID) == "" || strings.TrimSpace(body.TenantID) == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("connector-report: a connector id and the "+
				"organization it joined are both required — a connector filed under nobody is one no route "+
				"can be authored for"))
			return
		}
		reg.TenantID = body.TenantID
		// ★★★ AN ATTACHMENT REPORT TOUCHES ONE FIELD, AND ONLY WHEN THE AUTHORITY ALREADY HAS THE CONNECTOR.
		// The reporting node's copy of a registration comes FROM here and can be a generation behind, so
		// writing the whole record back on every tunnel attach would let a stale node undo an operator's
		// rename or their authored routes — a joining node erasing what somebody decided, which this
		// deployment has already been bitten by more than once. Where the connector is not known yet, the
		// registration is recorded as before, so the report is never simply lost.
		if region := strings.TrimSpace(body.AttachedRegionID); region != "" {
			if recorder, ok := registry.(connectorAttachmentRecorder); ok {
				if _, known := registry.Get(reg.ID); known {
					if _, err := recorder.RecordAttachedRegion(reg.ID, region); err != nil {
						writeError(w, http.StatusConflict, err)
						return
					}
					log.Printf("connector_attachment_report accepted from %q: %q is currently connected through %q",
						shipper.Identity, reg.ID, region)
					// ★★★ AND THE REST OF THE REPORT IS NOT THROWN AWAY (2026-09-01, found on the Console).
					//
					// This returned here, so a report that carried a region recorded ONLY the region. Once the
					// Edge began carrying a connector's liveness — its heartbeat, its status — every one of
					// those reports arrived, updated the attachment, and dropped the rest. The authority's
					// last_heartbeat therefore stayed frozen at the moment of registration, and a site with two
					// live connectors read "Down — 0 of 2 connectors online" for as long as it ran.
					//
					// Recording where a connector is and recording that it is alive are two facts in one
					// message; taking one and discarding the other is how a screen ends up telling an operator
					// the opposite of what is true.
					//
					// ★ AND ONLY WHAT THE REPORTER OWNS. Its copy of the registration is not the authority on
					// the fields an operator authored — a name it has not seen would be overwritten by a stale
					// report, which is what the guard on this path exists for. Liveness is the reporter's own
					// observation, so that, and nothing else, is taken.
					// ★ AND A DROP IS SAID OUT LOUD. This is the shape the whole of 2026-09-01 was about: a
					// value quietly not taken, and a screen that then tells an operator the opposite of what
					// is true. If the store cannot record liveness, or the report carried none, the log says
					// which — because the symptom otherwise is a site that reads Down for ever.
					live, recordable := registry.(connectorLivenessRecorder)
					switch {
					case !recordable:
						log.Printf("connector_liveness_dropped connector=%q: this control plane's connector "+
							"store cannot record liveness, so last_heartbeat will not move and every "+
							"connector will read offline", reg.ID)
					case strings.TrimSpace(reg.LastHeartbeatAt) == "":
						log.Printf("connector_liveness_dropped connector=%q: the report carried no heartbeat "+
							"time, so there is nothing to record", reg.ID)
					default:
						moved, err := live.RecordLiveness(reg.ID, reg.Status, reg.LastHeartbeatAt)
						if err != nil {
							writeError(w, http.StatusConflict, err)
							return
						}
						if moved {
							log.Printf("connector_liveness_recorded connector=%q heartbeat=%q status=%q",
								reg.ID, reg.LastHeartbeatAt, reg.Status)
						}
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
			reg.AttachedRegionID = region
		}
		if _, err := registry.Register(reg, time.Now()); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		log.Printf("connector_report accepted from %q: %q joined %q", shipper.Identity, reg.ID, body.TenantID)
		w.WriteHeader(http.StatusNoContent)
	})
}

func registerEnrolmentReportRoute(mux *http.ServeMux, ledger *enrolledinventory.Ledger,
	tenantCARegistry *tenantca.TenantCARegistry, configSourceURL string, devMode bool) {
	if ledger == nil {
		return
	}
	// A node that PULLS its configuration is not the authority for this ledger and must not write it — the
	// same rule the admin route states. Registering the door there would move the defect rather than fix it.
	if strings.TrimSpace(configSourceURL) != "" {
		return
	}
	mux.HandleFunc("POST /enrolment-report", func(w http.ResponseWriter, r *http.Request) {
		shipper, verified := auditIngestShipperFrom(r, tenantCARegistry)
		if !verified && !devMode {
			writeError(w, http.StatusForbidden, fmt.Errorf("enrolment-report: this request presents no Edge "+
				"certificate, so the enrolment could not be attributed to a node"))
			return
		}
		var body struct {
			Identity string `json:"identity"`
			TenantID string `json:"tenant_id"`
			Group    string `json:"group"`
			Note     string `json:"note"`
			// ★★★ THE FLEET REPORTS THROUGH THIS DOOR, NOT THE ADMIN ONE (2026-08-25, measured by walking a
			// rename on the two-region lab). The machine reference was added to the report body and to
			// POST /admin/enrolled-devices, and every Edge in the fleet uses THIS route — so the authority
			// learned nothing, each Edge knew only the machines it had issued to itself, and a renamed machine
			// enrolling against a different Edge was issued a SECOND identity. The distinction existed and was
			// per-node, which is the same shape as "one-time, once per Edge".
			MachineRef string `json:"machine_ref"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("enrolment-report: %w", err))
			return
		}
		identity := strings.TrimSpace(body.Identity)
		tenant := strings.TrimSpace(body.TenantID)
		if identity == "" || tenant == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("enrolment-report: an identity and the organization "+
				"it enrolled into are both required — a device filed under nobody is a device nothing enforces for"))
			return
		}
		note := strings.TrimSpace(body.Note)
		if note == "" {
			note = "enrolled on " + strings.TrimSpace(shipper.Identity)
		}
		now := time.Now().UTC().Format(time.RFC3339)
		// ★★★ RECORD, DO NOT RE-DECIDE (2026-08-24, measured — every report was answered 409). This used the
		// same call as the Edge's own /enroll, which TAKES the identity claim. The claim was already taken, by
		// the node that issued the certificate this report is about, and a claim at the same grant is refused
		// on purpose — that refusal is what makes two issuers racing produce one winner. Asking "may I issue
		// this?" about something already issued has exactly one correct answer.
		//
		// It still answers "is this identity disabled" and "does it already belong to another organization"
		// inside one ledger lock, so a report cannot move a machine between fleets.
		if _, err := ledger.RecordEnrolmentDecidedElsewhere(enrolledinventory.NormalizeIdentity(identity), tenant,
			strings.TrimSpace(body.Group), note, now); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		// Reported, not authored, and only when this deployment does not already know: an issuing node saying
		// which machine it issued to cannot use this to move a name to a different machine.
		if ref := strings.TrimSpace(body.MachineRef); ref != "" {
			if merr := ledger.RecordReportedMachine(enrolledinventory.NormalizeIdentity(identity), ref, now); merr != nil {
				log.Printf("enrolment_report: the machine reported for %q was NOT recorded (%v) — this "+
					"deployment cannot tell that machine from another of the same name, and a rename of it "+
					"would become a second device", identity, merr)
			}
		}
		log.Printf("enrolment_report accepted from %q: %q enrolled into %q machine=%q", shipper.Identity,
			identity, tenant, enrolledinventory.NormalizeMachineRef(body.MachineRef))
		w.WriteHeader(http.StatusNoContent)
	})
}

// organizationsThisControlPlaneHoldsAnythingFor is the union of the three tiers' organizations, sorted so an
// Edge's answer does not reorder between fetches for no reason.
//
// See the note at its call site: taking this from one tier is how an organization's own authority came to be
// authored, displayed, distributed to its devices, and used to sign nothing.
func organizationsThisControlPlaneHoldsAnythingFor(transport *tenantTransportAuthority,
	interception *tenantInterceptionAuthority, deviceIdentity *tenantDeviceAuthority) []string {

	seen := map[string]bool{}
	var out []string
	add := func(names []string) {
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	if transport != nil {
		add(transport.Organizations())
	}
	if interception != nil {
		add(interception.Organizations())
	}
	if deviceIdentity != nil {
		add(deviceIdentity.Organizations())
	}
	sort.Strings(out)
	return out
}
