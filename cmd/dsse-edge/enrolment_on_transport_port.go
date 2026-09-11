package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

// enrolment_on_transport_port.go — the enrolment fold: a device that holds NOTHING reaches the same port as one that holds
// everything.
//
// ★★★ THE GOAL IS IN THE DESIGN AND THE DEPLOYMENT CONTRADICTED IT (2026-08-21, measured). the enrolment fold says: "an
// agent touches ONE port, enrolment included; in production, 443 only", and three lines later, "a port like
// 8443 appearing in the configuration handed to an agent must not happen at all". The installer configuration
// this deployment ships carries "edge_url": "https://…:8443" — the exact thing it forbids.
//
// The same section had excluded 8443 from the count on the ground that agents arrive over (T). That is true
// only of a device that already HAS a certificate. Enrolment and the trust bundle are the entry for a device
// that has nothing, and the section names them itself. The wrong half was the excuse; it is corrected there.
//
// ★ THE FOLD IS SMALL BECAUSE THE PATHS ARE ALREADY THERE. The transport listener serves the same handler as
// the data port, so POST /enroll and GET /bootstrap/trust-bundle already answer on it. The only thing stopping
// a brand-new device is the handshake: the (T) configuration requires a client certificate, and a device being
// enrolled has none. So this is the same move the enrolment fold-1 made for the recovery path — a per-connection TLS
// configuration selected by SNI — with NoClientCert instead of RequireAnyClientCert.
//
// ★ AND THE MAIN CONFIGURATION IS NOT TOUCHED. Returned only for the enrolment name, from the hook that
// already exists; every other handshake proceeds byte-for-byte as before. A connection that arrives under this
// name reaches ONLY the paths a device with nothing can legitimately need — the same restriction the recovery
// name carries, for the same reason: a relaxed handshake must not become a way around mTLS for the rest.
//
// It changes nothing until an agent sends the name, which is why it can land before the agents do.
type enrolmentOnTransportPort struct {
	sni string
}

// enrolmentNamePrefix mirrors the recovery one: an organization's enrolment name is its own name with this in
// front, so the two folds share one shape and one place to look.
const enrolmentNamePrefix = "enrol."

// organizationEnrolmentName is the name a device of this organization dials when it holds nothing yet, or ""
// when the organization has no name of its own.
func organizationEnrolmentName(serverName string) string {
	n := strings.ToLower(strings.TrimSpace(serverName))
	if n == "" {
		return ""
	}
	return enrolmentNamePrefix + n
}

// isEnrolmentName answers whether a handshake asked for an enrolment name — either the deployment-wide one or
// an organization's own.
//
// ★ BOTH, BECAUSE A DEVICE MAY KNOW EITHER (2026-08-21). An installer that names the organization gives the
// device its own name; one that does not gives it the deployment's. Recognising only one would make the fold
// work for half the fleet and look like a device problem for the other half — the shape the enrolment fold already paid
// for once with the recovery name.
func isEnrolmentName(asked, deploymentWide string) bool {
	a := strings.ToLower(strings.TrimSpace(asked))
	if a == "" || !strings.HasPrefix(a, enrolmentNamePrefix) {
		return false
	}
	if d := strings.ToLower(strings.TrimSpace(deploymentWide)); d != "" && a == d {
		return true
	}
	// ★★★ AND ONLY IF SOME CERTIFICATE THIS NODE CAN SERVE ACTUALLY CARRIES IT (2026-08-21, caught by
	// measuring rather than by remembering — twice on the same day).
	//
	// The first guard checked the DEPLOYMENT-WIDE name and then let the prefix admit everything else, so a
	// name no certificate carries was still answered. It looked fine because the probe used curl -k. A real
	// device pins the transport CA from its installer configuration, so an offered name the certificate does
	// not carry fails verification — and the failure looks like the Edge being down, on the one path that
	// exists for a device holding nothing.
	//
	// An organization's own enrol.<name> is carried by its transport certificate, which the control plane
	// mints; the index below is built from the certificates this node actually holds, so this answers "will
	// the handshake produce a certificate that names this" rather than "does the string look right".
	if transportTenantCertificates != nil {
		if _, _, ok := transportTenantCertificates.For(a); ok {
			return true
		}
	}
	return false
}

var enrolmentTransportPort atomic.Pointer[enrolmentOnTransportPort]

// enrolmentPathsWithoutACertificate is everything a device that holds nothing may reach under the enrolment
// name. Deliberately a closed list rather than a prefix: this connection presented no certificate, so anything
// not on it is refused here rather than relying on a handler further in to notice.
func enrolmentPathsWithoutACertificate(path string) bool {
	switch strings.TrimSpace(path) {
	case "/enroll", "/bootstrap/trust-bundle", "/steer/agent-policy/pubkey", "/healthz":
		return true
	}
	return false
}

// enableEnrolmentOnTransportPort turns on the fold. The deployment-wide name is offered ONLY when the
// certificate this port serves carries it.
//
// ★★★ A FOLD THAT OFFERS A NAME NO CERTIFICATE CARRIES IS THE DEFECT THIS DEPLOYMENT ALREADY PAID FOR
// (2026-08-19 for the recovery name; re-introduced here on 2026-08-21 and caught by measuring rather than by
// remembering). A device that dials the name pins the transport CA from its installer configuration, so a
// certificate that does not carry the name fails verification — and the failure looks like the Edge being
// down, on the one path that exists for a device with nothing.
//
// Measured on this lab: the transport certificate carries localhost, the tailnet host, recovery.dsse.invalid
// and four addresses — and NOT enrol.dsse.invalid. The per-organization certificates do carry their own
// enrol.<name>, because the control plane mints them and the template was changed with this. So the
// per-organization half is offered and the deployment-wide half waits for that certificate to name it.
func enableEnrolmentOnTransportPort(sni string, servedNames []string) {
	name := strings.ToLower(strings.TrimSpace(sni))
	if name == "" {
		return
	}
	carried := false
	for _, n := range servedNames {
		if strings.EqualFold(strings.TrimSpace(n), name) {
			carried = true
			break
		}
	}
	if !carried {
		log.Printf("enrolment fold: the deployment-wide name %q is NOT offered, because the certificate this "+
			"port serves does not carry it (it carries %v). Organizations on their own transport authority are "+
			"unaffected — their certificates name enrol.<their name> and that half of the fold is live. Add %q "+
			"to the transport certificate to finish it; replacing that certificate breaks live tunnels, so it "+
			"is an operator's move, not a start-up one", name, servedNames, name)
		name = ""
	}
	enrolmentTransportPort.Store(&enrolmentOnTransportPort{sni: name})
	log.Printf("enrolment is also reachable on the transport port for enrol.<organization> (no client "+
		"certificate is asked for on those names, and ONLY the paths a device holding nothing can need are "+
		"served); deployment-wide name: %s. The data port stays until every agent has been given the name — "+
		"see the enrolment fold", map[bool]string{true: name, false: "not offered (the certificate does not carry it)"}[name != ""])
}

// enrolmentConfigFor returns the per-connection configuration for a handshake that asked for the enrolment
// name, and nil for every other handshake.
func enrolmentConfigFor(base *tls.Config, hello *tls.ClientHelloInfo) *tls.Config {
	e := enrolmentTransportPort.Load()
	if e == nil || hello == nil || base == nil {
		return nil
	}
	if !isEnrolmentName(hello.ServerName, e.sni) {
		return nil
	}
	per := base.Clone()
	per.GetConfigForClient = nil // terminal, like every other per-connection config here
	// A device being enrolled has nothing to present. Asking for a certificate it cannot have would fail the
	// handshake before the token it DOES have is ever read.
	per.ClientAuth = tls.NoClientCert
	per.ClientCAs = nil
	per.VerifyConnection = nil
	return per
}

// serveEnrolmentIfNamed dispatches a connection that arrived under the enrolment name, and reports whether it
// did. Anything else is left entirely alone.
func serveEnrolmentIfNamed(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
	e := enrolmentTransportPort.Load()
	if e == nil || r == nil || r.TLS == nil {
		return false
	}
	if !isEnrolmentName(r.TLS.ServerName, e.sni) {
		return false
	}
	if !enrolmentPathsWithoutACertificate(r.URL.Path) {
		writeError(w, http.StatusNotFound, fmt.Errorf("this connection asked for the enrolment name and "+
			"presented no certificate, so only enrolment and the trust bundle are served on it. Everything "+
			"else needs the device identity this path exists to obtain"))
		return true
	}
	next.ServeHTTP(w, r)
	return true
}
