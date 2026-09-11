package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"github.com/lantern-networks/dsse-core/enroll"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// enroll_renew_endpoint.go — certificate RENEWAL, authenticated by the certificate being renewed.
//
// Why this has to exist before short-lived device certs are used anywhere real: POST /enroll issues certs with
// a 60-day TTL and its own flag text promises they are "re-issued before expiry", but nothing performed that
// re-issue. Turning enrolment on as it stood would have put the whole fleet into a simultaneous mTLS failure on
// day 60. The same class of outage already happened once here with a 30-day leaf. Short-lived certificates are
// only safe WITH automated renewal; the automation has to land first.
// (, )
//
// AUTHENTICATION IS THE CURRENT CERTIFICATE — not the enrolment token. The enrolment token is a bootstrap
// secret handed out once; renewal happens for the lifetime of the device, so requiring it would force that
// secret to live on every endpoint forever. Instead this is served over the (T) mTLS transport, where the
// handshake has ALREADY established that the client cert chains to a registered tenant CA, names an identity
// present in the enrolled inventory, and is not revoked. A device that has been killed cannot renew, which is
// what makes revocation actually terminal rather than merely a 60-day countdown.
//
// THE IDENTITY IS TAKEN FROM THE VERIFIED CERTIFICATE, NEVER FROM THE REQUEST BODY. The CSR proves possession
// of a key and nothing else; letting it name a device would let any enrolled endpoint mint a certificate for
// any other one.

type renewResponse struct {
	CertPEM string `json:"cert_pem,omitempty"`
	CAPEM   string `json:"ca_pem,omitempty"`
	NotFrom string `json:"not_before,omitempty"`
	NotTo   string `json:"not_after,omitempty"`
	Error   string `json:"error,omitempty"`
}

// renewRequestPresentedCertificate is the certificate the device is holding at the moment it asks to renew.
// The recovery listener accepts an expired certificate WITHOUT Go verifying it, so VerifiedChains is empty
// there — the peer certificate is still present, and it is the peer certificate, not the verified chain,
// that answers "did the last renewal take?". Returns nil when there is nothing to judge.
func renewRequestPresentedCertificate(r *http.Request) *x509.Certificate {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

func registerEnrollRenewEndpoint(mux *http.ServeMux, signer *deviceca.Signer, ledger *enrolledinventory.Ledger, tenant string, certTTL time.Duration, logf func(string, ...interface{})) {
	registerEnrollRenewEndpointWithIdentity(mux, signer, ledger, tenant, certTTL, transportDeviceIdentityFromRequest, logf)
}

// registerEnrollRenewEndpointWithIdentity is the same endpoint with the identity source injected.
//
// The (T) transport takes the identity from r.TLS.VerifiedChains, because Go verified the chain and that value
// is its conclusion. The RECOVERY listener cannot: accepting an expired certificate means Go is not doing the
// verification, and Go leaves VerifiedChains EMPTY when it does not — so the default extractor returns nothing
// and every recovery request is refused with "no verified client certificate". That was found by running it,
// not by reading it.
//
// The issuance logic is shared rather than duplicated ON PURPOSE. This endpoint mints credentials; two copies
// of it would eventually disagree about who is allowed what, and the copy nobody looks at would be the
// permissive one.
// signerFor is the authority a given organization's devices are issued under, or nil when this node holds
// none for them. Same source as POST /enroll uses, so the two cannot disagree about which authority an
// organization's devices belong to.
func signerFor(tenant string) *deviceca.Signer { return tenantDeviceIdentity.For(tenant) }

// renewTenantOf is the organization the CONTROL PLANE says this device belongs to. Read from the ledger by
// the identity the verified certificate proved — never from the request, and never from the node's own
// configuration, which is what made every renewal a step back towards the deployment's CA.
func renewTenantOf(ledger *enrolledinventory.Ledger, identity string) string {
	if ledger == nil {
		return ""
	}
	entry, ok := ledger.EntryFor(identity)
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(entry.TenantID))
}

func registerEnrollRenewEndpointWithIdentity(mux *http.ServeMux, signer *deviceca.Signer, ledger *enrolledinventory.Ledger,
	tenant string, certTTL time.Duration, identityOf func(*http.Request) (string, bool), logf func(string, ...interface{})) {
	if signer == nil {
		return
	}
	adoptionGuard := newRenewAdoptionGuard()
	mux.HandleFunc("POST /enroll/renew", func(w http.ResponseWriter, r *http.Request) {
		identity, ok := identityOf(r)
		if !ok || strings.TrimSpace(identity) == "" {
			// Not on the mTLS transport, or no verified client cert. Renewal is only meaningful for a device
			// that already holds a valid certificate.
			writeJSON(w, http.StatusUnauthorized, renewResponse{
				Error: "renewal requires a verified client certificate on the (T) transport",
			})
			return
		}
		normalized := enrolledinventory.NormalizeIdentity(identity)

		// Defence in depth. The TLS admission gate already refuses an unenrolled or revoked identity before any
		// handler runs, so reaching here means the device is admitted — but renewal MINTS CREDENTIALS, so it
		// re-checks rather than inheriting the assumption.
		if ledger != nil && !ledger.IsAdmitted(normalized) {
			if logf != nil {
				logf("enroll_renew_refused identity=%q reason=%q", normalized, "not admitted in the enrolled inventory")
			}
			writeJSON(w, http.StatusForbidden, renewResponse{Error: "device is not admitted"})
			return
		}

		var body struct {
			CSRPEM string `json:"csr_pem"`
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err := json.Unmarshal(raw, &body); err != nil || strings.TrimSpace(body.CSRPEM) == "" {
			writeJSON(w, http.StatusBadRequest, renewResponse{Error: "csr_pem required"})
			return
		}

		// ★★★ AND UNDER THE DEVICE'S OWN ORGANIZATION'S AUTHORITY (2026-08-22, measured — this is the last
		// thing standing between this deployment and per-tenant device identity).
		//
		// POST /enroll picks the signer per organization (Issuer.SignerFor). This endpoint took ONE signer at
		// registration and used it for every device, whoever they belonged to — so a device enrolled under its
		// organization's authority was moved BACK to the node's on its first renewal, and a device enrolled
		// before the organization had one could never leave it. Measured on the lab: every device presented a
		// certificate from "Lantern DSSE Device Issuing CA", months after its organization had its own, and no
		// number of renewals would ever have changed that.
		//
		// The organization comes from the LEDGER, which is the control plane's answer, keyed by the identity
		// the verified certificate proved. Nothing the caller sends chooses it — the same rule as the group
		// below and the subject above.
		signWith, org := signer, tenant
		if deviceOrg := renewTenantOf(ledger, normalized); deviceOrg != "" {
			if own := signerFor(deviceOrg); own != nil {
				signWith, org = own, deviceOrg
			} else if !strings.EqualFold(deviceOrg, tenant) && logf != nil {
				// Said, not silently absorbed: renewing another organization's device under THIS node's
				// authority is exactly how a fleet ends up unable to leave the deployment's CA.
				logf("enroll_renew_no_tenant_authority identity=%q tenant=%q — this node holds no "+
					"device-identity authority for that organization, so the renewal is signed under the "+
					"node's own and that device cannot move onto its own", normalized, deviceOrg)
			}
		}

		// CP-authoritative subject, exactly as first issuance does: identity from the verified certificate,
		// group from the ledger. Nothing the caller sends influences who this certificate is for.
		subject := pkix.Name{CommonName: normalized, Organization: []string{org}}
		if g := cpAuthoritativeGroup(ledger, normalized); g != "" {
			subject.OrganizationalUnit = []string{g}
		}

		// Convergence. A renewal ends with the device presenting the new certificate; when it asks again
		// while still holding the old one, the previous renewal did not take and signing another identical
		// one will not change that. Spaced out and stated rather than refused outright — see the guard.
		presented := renewRequestPresentedCertificate(r)
		verdict := adoptionGuard.Check(normalized, presented, time.Now())
		if !verdict.Allow {
			if logf != nil {
				logf("enroll_renew_not_adopted identity=%q unadopted=%d previous_issued_at=%q retry_after=%s"+
					" reason=%q", normalized, verdict.Unadopted, verdict.PreviousIssuedAt.UTC().Format(time.RFC3339),
					verdict.RetryAfter, "a renewal was already issued and the device is still presenting the old certificate")
			}
			w.Header().Set("Retry-After", strconv.Itoa(int(verdict.RetryAfter.Seconds())))
			writeJSON(w, http.StatusTooManyRequests, renewResponse{
				Error: "a renewal was already issued for this device and has not been put into service yet",
			})
			return
		}

		certPEM, err := signWith.Sign([]byte(body.CSRPEM), subject, certTTL)
		if err != nil {
			if logf != nil {
				logf("enroll_renew_failed identity=%q error=%q", normalized, err.Error())
			}
			writeJSON(w, http.StatusBadRequest, renewResponse{Error: "could not sign the CSR"})
			return
		}
		unadopted := adoptionGuard.Recorded(normalized, presented, time.Now())
		if logf != nil {
			// Renewal is a credential-issuing event; it belongs in the audit trail even on the happy path.
			// unadopted says whether this is a fresh renewal or the Nth attempt to replace the same
			// certificate — a column of identical successes was exactly what hid the loop.
			logf("enroll_renewed identity=%q ttl=%s unadopted_attempts=%d", normalized, certTTL, unadopted)
		}
		// ★ AND THE DATES, WHICH THIS RESPONSE HAS DECLARED AND NEVER SENT (2026-08-23, measured). not_before
		// and not_after have been fields on renewResponse since it was written and no construction ever set
		// them, so every renewing client was told "" for when its new certificate expires. The connector's
		// renewal log read "valid until  " — a line that carries the shape of an answer and none of the answer.
		// Read back from the signed certificate rather than computed from the TTL, so what is reported is what
		// was actually issued.
		resp := renewResponse{CertPEM: string(certPEM), CAPEM: string(signWith.CAPEM())}
		if blk, _ := pem.Decode(certPEM); blk != nil {
			if issued, perr := x509.ParseCertificate(blk.Bytes); perr == nil {
				resp.NotFrom = issued.NotBefore.UTC().Format(time.RFC3339)
				resp.NotTo = issued.NotAfter.UTC().Format(time.RFC3339)
			}
		}
		writeJSON(w, http.StatusOK, resp)
	})
	if logf != nil {
		logf("enroll renewal endpoint registered: POST /enroll/renew (mTLS-authenticated, ttl=%s)", certTTL)
	}
}

// renewalDue reports whether a certificate should be renewed now, and is the ONE place that decision is made
// so the client and any server-side warning cannot drift apart.
//
// Renewal starts at two thirds of the certificate's life. That leaves a third of the validity as retry budget:
// with a 60-day certificate the device has 20 days of failed attempts before anything breaks, which is what
// turns a broken renewal path into an alert instead of an outage. Renewing at the last minute would remove
// exactly that margin.
// The rule itself now lives in the enroll package both this Edge and the connector import, because "the ONE
// place" above had become three copies and a connector's renewal was about to make a fourth with a different
// rule. This stays as the name the rest of this file uses.
func renewalDue(notBefore, notAfter, now time.Time) bool {
	return enroll.RenewalDue(notBefore, notAfter, now)
}
