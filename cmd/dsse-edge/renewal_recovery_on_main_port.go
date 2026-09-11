package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
)

// renewal_recovery_on_main_port.go — the enrolment fold step 3: the expired-certificate renewal path, reachable on the
// TRANSPORT port when the ClientHello asks for it by name.
//
// ★★★ THE MAIN CONFIGURATION IS NOT TOUCHED, AND THAT IS THE WHOLE DESIGN. The recovery path needs
// RequireAnyClientCert — Go's own verification would reject the expired certificate before anything of ours
// runs — and relaxing the main transport that way has exactly two outcomes, both catastrophic: a hole that
// accepts unverified certificates, or a check that locks out the fleet. So the relaxed configuration is
// returned ONLY for the recovery SNI, from the per-connection hook that already exists, and every other
// connection gets the configuration it got before, unchanged.
//
// The handler follows the same rule. A connection that arrived under the recovery name is served by the
// recovery mux — one handler, POST /enroll/renew — and never by the main mux. Not a filter over the main mux:
// a filtered subset grows when somebody adds a route elsewhere, and this must not.
//
// ★ IT CHANGES NOTHING UNTIL AN AGENT SENDS THE NAME, which is why it can land before the agents do. The
// dedicated listener stays up and keeps serving the same path on its own port; this only removes the reason
// that port has to exist. The port closes at step 5, after every enrolled device has been MEASURED onto a
// bundle carrying the name — with silence counted as "not yet", because the devices that need recovery are
// the ones that were switched off.
type renewalRecoveryOnMainPort struct {
	sni    string
	mux    *http.ServeMux
	verify func(tls.ConnectionState) error
}

var renewalRecoveryMainPort atomic.Pointer[renewalRecoveryOnMainPort]

// enableRenewalRecoveryOnMainPort wires the SNI-selected recovery path. Absent configuration disables it
// completely: no SNI, no branch, no behaviour change of any kind.
func enableRenewalRecoveryOnMainPort(sni string, cfg enrollRenewGraceConfig, pool *x509.CertPool) {
	name := strings.ToLower(strings.TrimSpace(sni))
	if name == "" || cfg.Signer == nil {
		return
	}
	renewalRecoveryMainPort.Store(&renewalRecoveryOnMainPort{
		sni:    name,
		mux:    enrollRenewGraceMux(cfg),
		verify: enrollRenewGraceVerify(cfg, pool),
	})
	log.Printf("renewal recovery is also reachable on the transport port for SNI %q (expired certificates "+
		"accepted for enrolled, non-revoked identities, and ONLY for POST /enroll/renew). The dedicated port "+
		"stays until every enrolled device has been measured onto a trust bundle that names this", name)
}

// enableRenewalRecoveryOnMainPortFrom builds the pool the same way the dedicated listener does and wires the
// SNI path. One function so the two cannot end up trusting different sets — the pool is the answer to "who is
// allowed to recover", and two answers to that is the defect this file is careful about everywhere else.
func enableRenewalRecoveryOnMainPortFrom(sni string, cfg enrollRenewGraceConfig) {
	if strings.TrimSpace(sni) == "" {
		return
	}
	// ★★★ CONFIGURED AND UNABLE IS NOT THE SAME AS NOT CONFIGURED, AND IT USED TO LOOK IDENTICAL (2026-08-19).
	//
	// This returned in silence when the node has no enrolment signer. Measured on region-b of the reference
	// lab: it carries the recovery flags and cannot issue a certificate, so neither the folded path nor the
	// dedicated listener ever came up — and NOTHING SAID SO, on a node whose whole purpose is to be the one a
	// device fails over to. An operator reading the compose file sees recovery configured on both regions.
	//
	// It is still not fatal: a node that cannot issue is a legitimate deployment, and refusing to start would
	// take the failover region down over a path it never served. But it must be audible, because the fleet
	// decision in the fold's last step is about what a device can reach ANYWHERE, not on the node it happens to poll.
	if cfg.Signer == nil {
		log.Printf("renewal recovery is CONFIGURED on this node (SNI %q) and cannot be served: this Edge has no "+
			"enrolment signer, so it can issue nothing. Neither the folded path nor the dedicated listener is "+
			"running here. A device that fails over to this node cannot recover an expired certificate on it — "+
			"it must reach an issuing Edge. Announce the ISSUER's recovery endpoint from this node.", sni)
		return
	}
	// The certificate must carry the name before the path that is selected by the name may be offered.
	leaf, which, cerr := certificateServedForRecoveryName(sni, cfg.ServerCert)
	if cerr != nil {
		log.Printf("renewal recovery on the transport port is NOT enabled: the certificate that would be served "+
			"for %q could not be read (%v) — devices keep recovering on the dedicated port", sni, cerr)
		return
	}
	if !recoveryNameIsInTheCertificate(sni, leaf) {
		log.Printf("renewal recovery on the transport port is NOT enabled: a handshake for %q is answered with "+
			"%s, which carries the names %v — a device checks that name against the anchors it adopted and "+
			"refuses this, and the devices that dial recovery are the ones whose own certificate has already "+
			"expired. Issue a certificate carrying %q (an act for whoever owns the signing CA, not for this "+
			"node) and restart. The dedicated recovery port stays open and keeps working.",
			sni, which, leaf.DNSNames, sni)
		return
	}
	pool, err := graceClientPool(cfg)
	if err != nil {
		log.Printf("renewal recovery on the transport port is NOT enabled (%v) — devices still recover on the "+
			"dedicated port, and the fold to one port waits for this to be configured", err)
		return
	}
	enableRenewalRecoveryOnMainPort(sni, cfg, pool)
}

// recoveryConfigFor returns the relaxed per-connection configuration when this handshake asked for the
// recovery name, and nil for every other handshake.
func recoveryConfigFor(base *tls.Config, hello *tls.ClientHelloInfo) *tls.Config {
	r := renewalRecoveryMainPort.Load()
	if r == nil || hello == nil || base == nil {
		return nil
	}
	if !isRecoveryName(hello.ServerName, r.sni) {
		return nil
	}
	per := base.Clone()
	per.GetConfigForClient = nil // terminal, like every other per-connection config here
	per.ClientAuth = tls.RequireAnyClientCert
	per.VerifyConnection = r.verify
	// The device-trust pool is deliberately NOT applied: the recovery verification does its own chain check
	// against the live pool, and leaving Go's verification in place is what rejects an expired certificate
	// before the code that is allowed to accept it ever runs.
	per.ClientCAs = nil
	return per
}

// serveRecoveryIfNamed dispatches a connection that arrived under the recovery name to the recovery mux, and
// reports whether it did. Anything else is left entirely alone.
func serveRecoveryIfNamed(w http.ResponseWriter, req *http.Request) bool {
	r := renewalRecoveryMainPort.Load()
	if r == nil || req == nil || req.TLS == nil {
		return false
	}
	// ★★★ THE SAME NAME, ASKED TWICE, AND ONLY ONE OF THE TWO FOLLOWED THE ANNOUNCEMENT (2026-08-21, measured
	// on win-dev-1 with a deliberately expired certificate — the first real run of this path).
	//
	// The handshake selector below (recoveryConfigFor -> isRecoveryName) learned about per-organization
	// recovery names when the announcement moved from recovery.dsse.invalid to recovery.<org>. This one did
	// not: it compared the SNI against the DEPLOYMENT-WIDE name alone. So a device arriving as
	// recovery.lab.dsse.invalid got the relaxed handshake — RequireAnyClientCert, expiry judged by the
	// recovery verifier — and was then handed to the ORDINARY mux, whose identity comes from
	// r.TLS.VerifiedChains. Go leaves that empty precisely because it did not verify the expired certificate,
	// so /enroll/renew answered:
	//
	//     HTTP 401  renewal requires a verified client certificate on the (T) transport
	//
	// which is backwards: a device that can present a verifiable certificate does not need this path at all.
	// With the dedicated recovery port already retired on the evidence that every device held the name, an
	// expired device had NO way back — the exact silent hole this fold exists to close, open only for machines
	// already in trouble.
	//
	// This is the mirror image of the enrolment fold's defect (6ee90b5f): one act, two selectors, one updated.
	// They now ask the same function.
	if !isRecoveryName(req.TLS.ServerName, r.sni) {
		return false
	}
	r.mux.ServeHTTP(w, req)
	return true
}

// renewalRecoveryAwareHandler sends a connection that arrived under the recovery name to the recovery mux, and
// every other connection to the handler it would have reached anyway.
//
// Wrapped only around the TRANSPORT listener's handler: the recovery path is an agent path, and putting this
// on the admin or data-plane listeners would be widening it for no reason.
func renewalRecoveryAwareHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveRecoveryIfNamed(w, r) {
			return
		}
		// ★ the enrolment fold: and the enrolment name, for a device that has nothing to renew because it has nothing.
		if serveEnrolmentIfNamed(w, r, next) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ★★★ AND IT IS NOT ENABLED UNLESS THE CERTIFICATE SERVED FOR THAT NAME CARRIES THE NAME (2026-08-19,
// measured from win-dev-1 and reproduced on the node that serves it).
//
// The fold selects the recovery path by SNI, and nothing made the certificate follow. Measured on the running
// Edge: a ClientHello for the recovery name is answered with the ordinary transport certificate, whose names
// are localhost, the host's tailnet name and four IP addresses. A client that checks the name — both agents do,
// against the anchors they adopted — refuses it. The live probe that was supposed to catch this was refused as
// an anonymous caller first, so the server's own answer hid the certificate's.
//
// ★ THE DEVICES THIS BREAKS ARE EXACTLY THE DEVICES IT EXISTS FOR. Recovery is dialled by a device whose own
// certificate has expired; if the fold answers with a name it cannot verify, that device has no path back at
// all, and it is switched off, so nobody hears about it. A silent hole that only opens for machines already in
// trouble is worse than no fold.
//
// The fix is to put the name in the certificate — and on this deployment that is an ISSUANCE act, not a
// configuration change: the certificates served here are signed by CAs whose keys this node does not hold (the
// shared one by the MSSP, by design; an organization's own by whoever owns it). Which is the ownership model
// working as intended, and it means the fold cannot repair itself. So until somebody issues a certificate that
// carries the name, this refuses to pretend: the SNI path stays off, the dedicated port keeps serving
// recovery, and the log says which certificate was checked and what names it actually has.
func recoveryNameIsInTheCertificate(sni string, served *x509.Certificate) bool {
	name := strings.ToLower(strings.TrimSpace(sni))
	if name == "" || served == nil {
		return false
	}
	// The name check the agents perform, and no more of it: SANs only. A CommonName that matches is not a
	// match — no TLS stack has honoured it for years, and accepting it here would enable the fold for
	// certificates the agents go on refusing.
	for _, dns := range served.DNSNames {
		if strings.EqualFold(strings.TrimSpace(dns), name) {
			return true
		}
		if wildcardCoversRecoveryName(dns, name) {
			return true
		}
	}
	return false
}

// wildcardCoversRecoveryName accepts *.example only for a name with exactly one more label, which is what a
// verifier will do with it.
func wildcardCoversRecoveryName(pattern, name string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	if !strings.HasPrefix(p, "*.") {
		return false
	}
	suffix := p[1:] // ".example"
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	return !strings.Contains(strings.TrimSuffix(name, suffix), ".")
}

// certificateServedForRecoveryName resolves the certificate this listener would actually hand back for that
// ClientHello — the organization's own when the index holds the name, the shared one otherwise. Resolved
// through the same seam the listener uses, so this cannot check one certificate while the handshake serves
// another.
func certificateServedForRecoveryName(sni, sharedCertFile string) (*x509.Certificate, string, error) {
	name := strings.ToLower(strings.TrimSpace(sni))
	if cert, tenant, ok := transportTenantCertificates.For(name); ok && cert != nil && len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, tenant, err
		}
		return leaf, tenant + "'s own transport certificate", nil
	}
	raw, err := os.ReadFile(sharedCertFile)
	if err != nil {
		return nil, "", err
	}
	block, _ := decodeFirstCertificatePEM(raw)
	if block == nil {
		return nil, "", fmt.Errorf("no certificate in %s", sharedCertFile)
	}
	leaf, err := x509.ParseCertificate(block)
	if err != nil {
		return nil, "", err
	}
	return leaf, "the shared transport certificate (" + sharedCertFile + ")", nil
}

func decodeFirstCertificatePEM(data []byte) ([]byte, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, nil
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes, nil
		}
	}
}

// isRecoveryName reports whether this handshake asked for A recovery name — the deployment's, or the one that
// belongs to an organization served here.
//
// ★★★ ONE RECOVERY NAME FOR EVERY ORGANIZATION WAS A LOCKOUT (2026-08-20, measured the night roadmap D
// finished for the first organization).
//
// The deployment-wide recovery name is answered with the deployment-wide certificate — it has to be, because a
// server chooses its certificate from the name and every organization was sending the same one. An organization
// that has moved onto its OWN authority no longer trusts that certificate: measured on the lab, a device
// holding one anchor verifies lab.dsse.invalid and REFUSES recovery.dsse.invalid. The dedicated recovery port
// had already been retired on the evidence that every device held the name — nobody had asked whether they
// could verify what answers to it.
//
// So an organization on its own authority is told a recovery name of its own, which its own certificate
// carries, and the selector stays what it has been everywhere else in this design: the name.
func isRecoveryName(asked, deploymentWide string) bool {
	name := strings.ToLower(strings.TrimSpace(asked))
	if name == "" {
		return false
	}
	if strings.EqualFold(name, strings.TrimSpace(deploymentWide)) {
		return true
	}
	if !strings.HasPrefix(name, recoveryNamePrefix) {
		return false
	}
	// It must be a name this node actually serves, so an unknown "recovery.*" cannot relax a handshake.
	_, _, ok := transportTenantCertificates.For(name)
	return ok
}

// recoveryNamePrefix is how an organization's recovery name is built from the name its devices already send:
// recovery.<server name>. Derived rather than configured, so the two cannot be given different answers.
const recoveryNamePrefix = "recovery."

// organizationRecoveryName is the recovery name for an organization's own server name, or "" when it has none.
func organizationRecoveryName(serverName string) string {
	n := strings.ToLower(strings.TrimSpace(serverName))
	if n == "" {
		return ""
	}
	return recoveryNamePrefix + n
}
