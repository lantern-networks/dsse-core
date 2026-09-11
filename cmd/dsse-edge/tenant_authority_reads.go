package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
)

// tenant_authority_reads.go — "what is this organization's device-identity / interception authority doing
// right now", answered by the node that HOLDS it.
//
// ★★★ WHY THIS EXISTS (2026-08-22, found by reading the multi-tenant PKI roadmap against the tree). Three
// tiers of per-organization authority had grown a full set of acts — create, rotate, abandon, promote,
// retire — and a readiness answer each. Only ONE of them could be READ:
//
//	GET /admin/tenant-transport-authority       existed
//	GET /admin/tenant-device-authority          ★ did not
//	GET /admin/tenant-interception-authority    ★ did not
//
// So a screen could show an organization's transport authority and could say nothing at all about the two
// tiers that decide whether its devices are admitted and whose root its traffic is inspected under. An
// operator's only way to see either was to perform an act and read the error. The rotation-readiness routes
// answer a different question — "may this movement finish" — and they live on an Edge, because only an Edge
// sees handshakes; these answer "what is here", and they live where the authority is.
//
// Both refuse in the same shape as their transport twin: a node that holds no authorities says so rather than
// reporting every organization as having none.

// certificateSummary is the part of a certificate a screen needs and a customer may see. Never any key
// material, and never the whole PEM — a fingerprint is what an operator compares, and the PEM is available
// from the distribution routes that exist for handing it out.
type certificateSummary struct {
	Subject   string `json:"subject"`
	SHA256    string `json:"sha256"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

func summarizeCertificatePEM(pemText string) (certificateSummary, bool) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil {
		return certificateSummary{}, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certificateSummary{}, false
	}
	return certificateSummary{
		Subject:   cert.Subject.String(),
		SHA256:    certFingerprint(cert),
		NotBefore: cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:  cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
	}, true
}

func registerTenantAuthorityReadRoutes(mux *http.ServeMux,
	adminEndpoint func(string, http.HandlerFunc) http.HandlerFunc,
	device *tenantDeviceAuthority, interception *tenantInterceptionAuthority, gates ...pkiTransitionAdmission) {

	// The organization named by the request, checked the same way every other per-organization PKI read is.
	target := func(w http.ResponseWriter, r *http.Request, act string) (string, bool) {
		tenant := strings.TrimSpace(adminTenantIDFromRequest(r))
		if tenant == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("this request names no organization"))
			return "", false
		}
		if err := adminTenantPKITargetAllowed(r, tenant, act); err != nil {
			writeError(w, http.StatusForbidden, err)
			return "", false
		}
		return tenant, true
	}

	mux.HandleFunc("GET /admin/tenant-device-authority", adminEndpoint("admin.certs.read|admin.tenant.admin",
		func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := target(w, r, "reading the device-identity authority of")
			if !ok {
				return
			}
			if device == nil {
				writeError(w, http.StatusConflict, fmt.Errorf(
					"this node holds no per-organization device-identity authorities, so it cannot say whether "+
						"%q has one — that is a CONTROL PLANE's answer, and answering it from here would report "+
						"every organization as having none. Ask the control plane", tenant))
				return
			}
			snapshot, err := device.materialSnapshot()
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, err)
				return
			}
			stored, known := snapshot.cas[strings.ToLower(tenant)]
			var row storedTenantDeviceCA
			if known && stored != nil {
				row = copyAuthority(*stored)
			} else {
				known = false
			}
			answer := map[string]any{
				"schema_version": "admin_tenant_device_authority.v1",
				"tenant_id":      tenant,
				"has_authority":  known,
				"rotating":       false,
			}
			if !known {
				answer["note"] = "This organization's devices are enrolled under the deployment's own " +
					"authority. Give it one before its devices can be admitted on nothing but its own."
				writeJSON(w, http.StatusOK, answer)
				return
			}
			if summary, ok := summarizeCertificatePEM(row.CACertPEM); ok {
				answer["signing"] = summary
			}
			answer["created_at"] = row.CreatedAt
			if row.Incoming != nil {
				answer["rotating"] = true
				answer["rotation_abandoned"] = row.IncomingWithdrawn
				if summary, ok := summarizeCertificatePEM(row.Incoming.CACertPEM); ok {
					answer["incoming"] = summary
				}
				answer["incoming_since"] = row.Incoming.CreatedAt
				// ★ WHICH ONE SIGNS IS THE FACT AN OPERATOR IS ACTUALLY ASKING FOR, and during a rotation it
				// is NOT the outer row — the incoming authority signs, because that is how devices migrate.
				// After an abandonment it is the outer row again while both stay admitted. A screen that
				// showed only "rotating: true" could not tell those two apart, and they are opposite states.
				if row.IncomingWithdrawn {
					answer["note"] = "This rotation was abandoned: new certificates come from the authority " +
						"in force again, and BOTH are still admitted so devices issued during the overlap " +
						"keep working. Retiring now drops the abandoned one."
				} else {
					answer["note"] = "Rotating: the incoming authority signs every new enrolment and renewal, " +
						"and both are admitted. Request readiness=1 on this control-plane read to verify " +
						"retirement conditions; the retirement POST always checks the evidence again."
				}
			}
			if r.URL.Query().Get("readiness") == "1" && row.Incoming != nil {
				answer["retirement_readiness"] = previewDeviceRetirement(snapshot, tenant, gates)
			}
			writeJSON(w, http.StatusOK, answer)
		}))

	mux.HandleFunc("GET /admin/tenant-interception-authority", adminEndpoint("admin.certs.read|admin.tenant.admin",
		func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := target(w, r, "reading the interception authority of")
			if !ok {
				return
			}
			if interception == nil {
				writeError(w, http.StatusConflict, fmt.Errorf(
					"this node holds no per-organization interception authorities, so it cannot say whether "+
						"%q has one — that is a CONTROL PLANE's answer, and answering it from here would report "+
						"every organization as having none. Ask the control plane", tenant))
				return
			}
			row, known := interception.Row(tenant)
			answer := map[string]any{
				"schema_version": "admin_tenant_interception_authority.v1",
				"tenant_id":      tenant,
				"has_authority":  known,
				"staged":         false,
			}
			if !known {
				answer["note"] = "This organization's traffic is inspected under the deployment's own root. " +
					"Its own root is the organization's to create; this deployment is handed an issuing tier " +
					"signed under it and never holds the root key."
				writeJSON(w, http.StatusOK, answer)
				return
			}
			if summary, ok := summarizeCertificatePEM(row.RootPEM); ok {
				answer["root"] = summary
			}
			if summary, ok := summarizeCertificatePEM(row.IssuingCertPEM); ok {
				answer["issuing"] = summary
			}
			answer["imported_at"] = row.ImportedAt
			if row.Incoming != nil {
				answer["staged"] = true
				if summary, ok := summarizeCertificatePEM(row.Incoming.RootPEM); ok {
					answer["incoming_root"] = summary
				}
				if summary, ok := summarizeCertificatePEM(row.Incoming.IssuingCertPEM); ok {
					answer["incoming_issuing"] = summary
				}
				answer["incoming_since"] = row.Incoming.ImportedAt
				// ★ STAGED IS NOT IN USE, and saying so is the whole reason the staging exists. Promoting
				// before every device holds the incoming root took eighteen minutes of every HTTPS site away
				// from this lab on 2026-08-19.
				answer["note"] = "Staged and NOT signing. Every device must hold the incoming root before it " +
					"is promoted — read GET /admin/interception-authority-rotation on an Edge. It can also be " +
					"withdrawn, which takes nothing away."
			}
			writeJSON(w, http.StatusOK, answer)
		}))
}
