package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
)

// Fleet device-certificate admin routes (renew-before cutoff set/clear + fleet
// certificate health). // Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerDeviceCertificateRoutes(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, writer *logs.Writer, deviceStore deviceRuntimeStore, edgeRenewBefore *renewBeforeSetting) {
	mux.HandleFunc("POST /admin/device-certificates/renew-all", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ THE RENEWAL ORDER IS THE WHOLE NODE'S, AND A CUSTOMER COULD PLACE AND CANCEL IT (2026-08-22,
		// measured). edgeRenewBefore is ONE value on this node — the route is named "fleet", and its own answer
		// says "Every device whose certificate was issued before this time will renew". Nothing about it names
		// an organization; the only tenant in the handler is the one stamped on the AUDIT row, which filed a
		// deployment-wide act under whichever customer performed it.
		//
		// Measured with tenant_northwind's own administrator, roles ["admin"], no cross-organization permission
		// and holding admin.endpoints.write like every tenant administrator does: the operator placed a
		// fleet-wide renewal order, and that customer cancelled it — {"cleared":true}, HTTP 200. An order
		// placed as part of a CA rotation is exactly the kind that gets cancelled that way, silently, by
		// somebody with no relationship to the fleet. Setting one is the other direction: every device in every
		// organization renewing at once, on one customer's say-so.
		//
		// Gated as the deployment-wide act it is. The permission is NOT moved: admin.endpoints.write also
		// covers a customer's own device administration — enable, disable, groups — and widening it would take
		// that away to close this, which is the mistake the role table warns about by name.
		//
		// ★ THE DEEPER FIX IS A PER-ORGANIZATION ORDER, and it is not this. Making the cutoff per organization
		// means the agent-policy route must resolve it per device, which is a real change to what every agent
		// is told; it belongs in daylight, not behind a gate written at three in the morning.
		if !adminOperatorOnlyOrganizationAct(w, r, "ordering every device on this deployment to renew its certificate") {
			return
		}
		var req struct {
			IssuedBefore string `json:"issued_before"`
		}
		_ = decodeLimitedJSONBody(w, r, &req, maxEdgeRuntimeJSONBodyBytes)
		at := time.Now().UTC()
		if v := strings.TrimSpace(req.IssuedBefore); v != "" {
			parsed, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Errorf("issued_before must be RFC3339: %w", err))
				return
			}
			at = parsed.UTC()
		}
		if err := edgeRenewBefore.Set(at); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("record the renewal request: %w", err))
			return
		}
		affected := []string{}
		for _, fact := range deviceCertificates.snapshot() {
			if issued, perr := time.Parse(time.RFC3339, fact.NotBefore); perr == nil && issued.Before(at) {
				affected = append(affected, fact.Identity)
			}
		}
		recordPKIMaterialChange(writer, r, evaluator, adminTenantIDFromRequest(r),
			"device_certificate_renewal_requested", "fleet", at.Format(time.RFC3339),
			"Every device whose certificate was issued before this time will renew the next time it asks.",
			map[string]any{"issued_before": at.Format(time.RFC3339), "known_affected": affected})
		logInfof("device_certificate_renewal_requested issued_before=%s known_affected=%d", at.Format(time.RFC3339), len(affected))
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version": "admin_device_certificate_renewal.v1",
			"issued_before":  at.Format(time.RFC3339),
			"known_affected": affected,
			"note":           "Devices act on this when they next fetch their policy. One that is switched off renews when it returns rather than being missed.",
		})
	}))
	mux.HandleFunc("DELETE /admin/device-certificates/renew-all", adminEndpoint("admin.endpoints.write", func(w http.ResponseWriter, r *http.Request) {
		// ★★★ The measured half: a customer administrator cancelled the operator's fleet-wide renewal order.
		// See the note on the POST above.
		if !adminOperatorOnlyOrganizationAct(w, r, "cancelling this deployment's certificate renewal order") {
			return
		}
		if err := edgeRenewBefore.Clear(); err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("clear the renewal request: %w", err))
			return
		}
		logInfof("device_certificate_renewal_request_cleared")
		// Nothing is undone by this: a certificate that was already renewed is simply a newer certificate.
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "admin_device_certificate_renewal.v1", "cleared": true})
	}))
	// Fleet certificate health: when each device's certificate expires, observed from the one it is presenting.
	// Automatic renewal has worked for a while; what was missing was any way to notice it had stopped, and the
	// way that failure arrives is every device expiring on the same day at once.
	mux.HandleFunc("GET /admin/device-certificates", adminEndpoint("admin.endpoints.read", func(w http.ResponseWriter, r *http.Request) {
		// ★ SCOPED TO THE CALLER'S TENANT (2026-08-15). This returned every observed device certificate on the
		// node, and named every enrolled device on it in not_seen. MEASURED on the reference lab once a second
		// tenant finally had a device: signed in as an ordinary `admin` of tenant_reference_lab — no
		// cross-tenant rights of any kind — the response listed `nw-laptop-001`, which belongs to
		// tenant_northwind, and counted it in enrolled_devices. After the fix that same call returns only its
		// own three, while reading as tenant_northwind still returns nw-laptop-001: the device is hidden from
		// the wrong tenant, not removed from the product, which is the half of the check a negative test cannot
		// make on its own. The presence route next door had the same hole and the same cause: with one tenant
		// on the lab, an unscoped read and a scoped one return exactly the same thing.
		callerTenant := adminTenantIDFromRequest(r)
		// Which tenant's OBSERVATIONS annotate these rows. The caller's when this deployment can scope them;
		// this node's own bundle tenant when it cannot, which is what the route did before and is still the
		// truthful answer for a deployment with no tenant model — not an empty string, which matches nothing
		// and would silently drop every fallback-expiry annotation on exactly those deployments.
		observationTenant := callerTenant
		if strings.TrimSpace(observationTenant) == "" {
			observationTenant = evaluator.PolicyBundle.TenantID
		}
		facts := []deviceCertificateFact{}
		unattributable := 0
		for _, f := range deviceCertificates.snapshot() {
			belongs, placeable := identityBelongsToTenant(config.EnrolledLedger, f.Identity, callerTenant)
			if !placeable {
				unattributable++
				continue
			}
			if belongs {
				facts = append(facts, f)
			}
		}
		// Each device's FALLBACK credential beside the one it presents. The fallback is what a device is
		// standing on when its renewed identity breaks, and since the bootstrap re-provisioning of
		// 2026-08-02 those are ordinary 60-day certificates rather than ten-year ones — an expiry nobody
		// is shown arrives as a device that cannot fall back, discovered only during the incident that
		// needed the fallback.
		type deviceCertificateWithFallback struct {
			deviceCertificateFact
			FallbackIssuerCN string `json:"fallback_issuer_common_name,omitempty"`
			FallbackNotAfter string `json:"fallback_not_after,omitempty"`
			FallbackDaysLeft int    `json:"fallback_days_left,omitempty"`
			FallbackExpired  bool   `json:"fallback_expired,omitempty"`
		}
		withFallback := make([]deviceCertificateWithFallback, 0, len(facts))
		for _, f := range facts {
			row := deviceCertificateWithFallback{deviceCertificateFact: f}
			if config.ObservedExclusions != nil {
				// The CALLER's tenant, not this node's. On a multi-tenant Edge the node's own tenant is not the
				// tenant of the device being described, so this looked up one customer's observations to
				// annotate another's device.
				page := config.ObservedExclusions.Query(observationTenant,
					observedQueryFilter{Device: f.Identity, Limit: 1})
				if len(page.Entries) > 0 && strings.TrimSpace(page.Entries[0].FallbackClientCertPEM) != "" {
					if block, _ := pem.Decode([]byte(page.Entries[0].FallbackClientCertPEM)); block != nil {
						if fb, err := x509.ParseCertificate(block.Bytes); err == nil {
							row.FallbackIssuerCN = fb.Issuer.CommonName
							row.FallbackNotAfter = fb.NotAfter.UTC().Format(time.RFC3339)
							row.FallbackDaysLeft = int(time.Until(fb.NotAfter).Hours() / 24)
							row.FallbackExpired = time.Now().After(fb.NotAfter)
						}
					}
				}
			}
			withFallback = append(withFallback, row)
		}
		// Devices that have never connected since this node started have no observation, and saying so is the
		// difference between "nothing is expiring" and "we have not seen them".
		var enrolled, unseen []string
		if config.EnrolledLedger != nil {
			seen := map[string]bool{}
			for _, f := range facts {
				seen[strings.ToLower(strings.TrimSpace(f.Identity))] = true
			}
			for _, e := range config.EnrolledLedger.List() {
				if !e.Enabled {
					continue
				}
				// The caller's own tenant only. ★ This is where the leak actually surfaced: the certificate rows
				// were one part of it, and this list named every OTHER tenant's device identities outright, in
				// not_seen, to any admin who asked. Same predicate as the enrolled-device screens, so an
				// unscoped deployment still sees its whole fleet here.
				if !deviceGroupVisibleToTenant(e.TenantID, callerTenant) {
					continue
				}
				enrolled = append(enrolled, e.Identity)
				if !seen[strings.ToLower(strings.TrimSpace(e.Identity))] {
					unseen = append(unseen, e.Identity)
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"schema_version":   "admin_device_certificates.v1",
			"certificates":     withFallback,
			"enrolled_devices": len(enrolled),
			"not_seen":         unseen,
			// Certificates observed on this node that the enrolled ledger cannot attribute to a tenant. Shown
			// rather than silently dropped: a count that quietly shrinks reads as a healthier fleet.
			"withheld_unattributable": unattributable,
			"note":                    "Observed at the transport handshake, so this is the certificate each device is really using. Devices that have not connected since this node started appear under not_seen rather than as a problem.",
		})
	}))
	// The anchors themselves, with each one's adoption — the information the staged rotation needs and that
	// used to exist only as a startup log line.
	// Durable: losing an operator's assertions on restart would re-close a gate they had deliberately opened,
	// with nothing on the screen to say why it had changed its mind.
	// An assertion has to outlive the machine that took it: the node judging a withdrawal is whichever
	// control plane leads then, not the one the operator was talking to. See the store's own note.
	if config.TransportAnchorAckSharedStore != nil {
		transportAnchorAcks = newSharedTransportAnchorAcknowledgements(config.TransportAnchorAckSharedStore)
	} else {
		transportAnchorAcks = newTransportAnchorAcknowledgements(config.TransportAnchorAckStorePath)
	}
}

// Transport-CA rotation readiness (which devices already trust the candidate anchor).
// Moved verbatim out of newServerWithConfig (Phase 2 route-registration split,
func registerTransportCAReadinessRoute(mux *http.ServeMux, adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc, config serverConfig, evaluator decision.Evaluator, deviceStore deviceRuntimeStore) {
	mux.HandleFunc("GET /admin/transport-ca-readiness", adminEndpoint("admin.steering.read", func(w http.ResponseWriter, r *http.Request) {
		fingerprint := strings.TrimSpace(r.URL.Query().Get("sha256"))
		if fingerprint == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("sha256 of the CA to check is required"))
			return
		}
		if config.ObservedExclusions == nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("device telemetry is not enabled, so readiness cannot be known"))
			return
		}
		// ★★ THE ANSWER IS ABOUT THE ORGANIZATION ASKING, NOT ABOUT THE NODE (2026-08-18). This read the
		// tenant from evaluator.PolicyBundle.TenantID — the NODE's own organization — and built the device
		// list from the whole enrolled inventory. So a customer asking whether their fleet had picked up a CA
		// got an answer computed over every organization on this Edge, with the identities in it: Ready,
		// NotReady, Silent and NeverReportedAnything are all lists of device names.
		//
		// Two defects in one line. The readiness was about somebody else's fleet, and the names came with it.
		// adminAnswerScope answers the first — an operator who has not entered an organization still gets the
		// deployment — and the ledger filter answers the second.
		tenantID, wholeDeployment := adminAnswerScope(r)
		if wholeDeployment {
			tenantID = evaluator.PolicyBundle.TenantID
		}
		// The device list comes from the ENROLLED INVENTORY, not from telemetry. Deriving it from telemetry
		// would report a fleet 100% ready precisely because the devices missing the CA are the ones not
		// talking — the failure this endpoint exists to prevent.
		var known []string
		var notAdopters []string
		if config.EnrolledLedger != nil {
			for _, entry := range config.EnrolledLedger.List() {
				// Only ENABLED devices. A disabled one is not coming back regardless of which CA it holds, and
				// counting it would keep readiness permanently short of complete.
				if !entry.Enabled {
					continue
				}
				if !wholeDeployment && !deviceGroupVisibleToTenant(entry.TenantID, adminTenantIDFromRequest(r)) {
					continue
				}
				// ★ ONLY IDENTITIES THAT ADOPT TRUST BUNDLES (2026-08-19). This question is "has every device
				// taken the distribution that carries this CA", and a service identity — a connector — never
				// takes one: it pins the Edge CA handed to it at enrolment and never reads a bundle. Counting
				// it makes the answer permanently short of complete for a client the withdrawal cannot reach,
				// which is how roadmap D's last step sat blocked on a component it does not affect.
				//
				// The ledger's own Kind answers this and answers it the same way on every Edge; the recovery
				// gate uses the same rule. What must not happen is dropping them quietly, so the response
				// names them.
				if !entry.IsEndpoint() {
					notAdopters = append(notAdopters, entry.Identity)
					continue
				}
				known = append(known, entry.Identity)
			}
		}
		readiness := config.ObservedExclusions.TransportCAReadiness(tenantID, fingerprint, known)
		readiness.NotAdopters = notAdopters
		writeJSON(w, http.StatusOK, readiness)
	}))
}
