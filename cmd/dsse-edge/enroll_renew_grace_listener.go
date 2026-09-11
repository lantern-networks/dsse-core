package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	certreload "github.com/lantern-networks/dsse-core/certreload"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/revocation"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// enroll_renew_grace_listener.go — letting a device that was switched off too long recover by itself.
//
// THE PROBLEM (raised by the operator, 2026-07-28: "make it safe to leave a device shut down over a long
// holiday"). Renewal authenticates with the certificate being renewed. That is deliberate and good — it means
// no bootstrap secret has to live on endpoints forever, and a revoked device cannot renew. But it has a sharp
// edge: once the certificate has actually EXPIRED, the device cannot complete the (T) handshake at all, so it
// cannot even ASK to renew. A laptop left off across its expiry comes back permanently dead and needs a human
// to re-enrol it. With 60-day certificates, being away for a month at the wrong point in the cycle is enough.
// A fleet where a summer holiday costs a support ticket per laptop is not a fleet anyone will run.
//
// WHY A GRACE WINDOW IS THE RIGHT ANSWER HERE, and not a weakening. In this product, admission authority is
// the operator's explicit block — that is the stated invariant behind the kill-switch, and why automatic
// signals were removed from it. Certificate expiry is credential hygiene, not an admission decision. Letting
// expiry act as a de-facto revocation would therefore contradict the model the rest of the system is built
// on. Revocation stays terminal; expiry becomes recoverable.
//
// WHY A SEPARATE LISTENER, rather than relaxing the (T) transport. Accepting an expired certificate means
// taking over chain verification from Go, and Go does not populate VerifiedChains when it is not doing the
// verification itself — which is the value every downstream identity check on the data plane reads. Relaxing
// the main listener would put a hand-rolled verification in the path of ALL steered traffic to solve a problem
// that only concerns one endpoint. A separate listener bounds the blast radius by construction: the only thing
// reachable through the relaxed path is renewal, and renewal can only mint a certificate for the identity
// named in the certificate presented, for a device that is still enrolled and not revoked.
//
// WHAT IS STILL ENFORCED on this listener — everything except the expiry itself:
//   - the certificate must chain to a registered tenant CA (verified as of just before its own expiry)
//   - the identity must be present and enabled in the enrolled inventory
//   - the identity must not be revoked — a killed device cannot come back this way
//   - the certificate must be expired by no more than the configured window
//
// Every recovery is logged as a security-relevant event, because "a device reappeared with a credential that
// had been dead for three weeks" is something an operator should see, not something to discover in aggregate.

type enrollRenewGraceConfig struct {
	Listen         string
	ServerCert     string
	ServerKey      string
	ClientCAFile   string
	TenantRegistry *tenantca.TenantCARegistry
	Ledger         *enrolledinventory.Ledger
	Revocations    *revocation.AdmissionRevocations
	Signer         *deviceca.Signer
	Tenant         string
	CertTTL        time.Duration
	// Window bounds how long after expiry a device may still recover. Bounded and explicit rather than
	// unlimited: the further past expiry, the less the certificate says about the device still being the one
	// that was enrolled.
	Window time.Duration
}

// graceClientPool assembles the CAs a recovering device's certificate may chain to — the same sources the (T)
// transport trusts, so this cannot accept an issuer the main path would not.
func graceClientPool(cfg enrollRenewGraceConfig) (*x509.CertPool, error) {
	var pool *x509.CertPool
	if cfg.TenantRegistry != nil && cfg.TenantRegistry.Pool != nil {
		pool = cfg.TenantRegistry.Pool.Clone()
	}
	if strings.TrimSpace(cfg.ClientCAFile) != "" {
		caPEM, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read renewal-grace client CA: %w", err)
		}
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("renewal-grace client CA file contained no usable certificates")
		}
	}
	if pool == nil {
		return nil, fmt.Errorf("renewal-grace listener needs a client CA (tenant registry or CA file)")
	}
	return pool, nil
}

// verifyRecoveringClient performs the verification Go would normally do, with expiry handled explicitly.
//
// Returns the identity on success. Every rejection reason is distinct so an operator can tell "the window has
// passed" from "this device is revoked" — they call for completely different actions.
func verifyRecoveringClient(leaf *x509.Certificate, intermediates []*x509.Certificate,
	pool *x509.CertPool, cfg enrollRenewGraceConfig, now time.Time) (string, error) {
	if leaf == nil {
		return "", fmt.Errorf("no client certificate")
	}

	// Chain verification AS OF just before the certificate's own expiry. This is the one and only concession:
	// the chain must have been genuinely valid, we simply do not require it to be valid *now*.
	asOf := leaf.NotAfter.Add(-time.Second)
	if now.Before(asOf) {
		// Not expired at all — this listener is not for it. Send it to the normal transport rather than
		// quietly serving a healthy device through the relaxed path.
		return "", fmt.Errorf("certificate is still valid; renew over the normal transport")
	}
	if now.Sub(leaf.NotAfter) > cfg.Window {
		return "", fmt.Errorf("certificate expired %s ago, beyond the %s recovery window",
			now.Sub(leaf.NotAfter).Round(time.Hour), cfg.Window)
	}

	inter := x509.NewCertPool()
	for _, c := range intermediates {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		CurrentTime:   asOf,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return "", fmt.Errorf("certificate does not chain to a trusted CA: %w", err)
	}

	// tenant binding — the SAME rule the (T) transport applies (secure_transport.go). The trusted pool is
	// the whole multi-tenant registry, so chaining successfully only proves the certificate came from SOME
	// tenant. Without this, a device holding an expired certificate from tenant B could recover against tenant
	// A's listener and be ISSUED a tenant-A certificate — identities are matched by name, so any collision
	// across tenants is a cross-tenant credential grant. Gated identically to the transport (registry present
	// AND an expected tenant configured) so the recovery path can never be laxer, nor stricter, than (T).
	if cfg.TenantRegistry != nil && strings.TrimSpace(cfg.Tenant) != "" {
		tid, ok := cfg.TenantRegistry.TenantForVerifiedChains(chains)
		if !ok {
			return "", fmt.Errorf("certificate does not chain to a registered tenant CA")
		}
		if tid != strings.TrimSpace(cfg.Tenant) {
			return "", fmt.Errorf("cross-tenant certificate (tenant %q != %q)", tid, strings.TrimSpace(cfg.Tenant))
		}
	}

	identity := transportIdentityFromLeaf(leaf)
	if strings.TrimSpace(identity) == "" {
		return "", fmt.Errorf("certificate has no usable identity")
	}

	// Revocation stays terminal. A device that was killed must not be able to return through the recovery
	// path — otherwise "revoked" would mean "revoked until its certificate expires", which is the opposite of
	// what the kill-switch is for.
	if cfg.Revocations != nil {
		if reason, gone := cfg.Revocations.IsRevoked(identity); gone {
			return "", fmt.Errorf("identity %q is revoked (%s)", identity, reason)
		}
	}
	if cfg.Ledger != nil && !cfg.Ledger.IsAdmitted(identity) {
		return "", fmt.Errorf("identity %q is not enrolled", identity)
	}
	return identity, nil
}

// startEnrollRenewGraceListener serves POST /enroll/renew, and nothing else, to devices whose certificate has
// expired within the recovery window.
func startEnrollRenewGraceListener(cfg enrollRenewGraceConfig) error {
	if strings.TrimSpace(cfg.Listen) == "" {
		return nil
	}
	// ★ Configured and unable is not the same as not configured — see renewal_recovery_on_main_port.go. This
	// returned nil in silence on a node with no enrolment signer, so a listener an operator had configured
	// simply was not there, and the start-up log looked exactly like a node that had never been asked for one.
	if cfg.Signer == nil {
		log.Printf("renewal RECOVERY listener is configured on %s and NOT started: this Edge has no enrolment "+
			"signer. Devices that fail over here cannot recover an expired certificate on this node.", cfg.Listen)
		return nil
	}
	if cfg.Window <= 0 {
		return fmt.Errorf("renewal-grace listener needs a positive -enroll-renew-grace-window")
	}
	pool, err := graceClientPool(cfg)
	if err != nil {
		return err
	}
	// The same hot-reloadable certificate as the (T) transport (same backing files, same derived name), so
	// one replacement through the admin surface updates both listeners together — a recovery listener serving
	// yesterday's identity would be unreachable to exactly the devices that need it.
	serverCert, err := certreload.NewReloadableCert(cfg.ServerCert, cfg.ServerKey)
	if err != nil {
		return fmt.Errorf("load renewal-grace server certificate: %w", err)
	}
	certreload.RegisterReloadable(serverCert)

	mux := enrollRenewGraceMux(cfg)

	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		CipherSuites:   edgeTLS12CipherSuites,
		GetCertificate: serverCert.GetCertificate,
		// RequireAnyClientCert, because Go's own verification would reject the expired certificate before we
		// ever see it. Everything Go would have checked is checked below instead.
		ClientAuth:       tls.RequireAnyClientCert,
		VerifyConnection: enrollRenewGraceVerify(cfg, pool),
	}
	return startEnrollRenewGraceServer(cfg, mux, tlsCfg)
}

// enrollRenewGraceMux is the recovery path's handler set, built in one place so the dedicated listener and the
// SNI-selected path on the main port cannot drift into serving different things.
//
// ONE endpoint. Not a filtered subset of the main mux — a mux containing exactly one handler, so nothing
// else can become reachable here by being added elsewhere later.
func enrollRenewGraceMux(cfg enrollRenewGraceConfig) *http.ServeMux {
	mux := http.NewServeMux()
	//
	// The identity comes from the PRESENTED certificate rather than from VerifiedChains, which Go leaves empty
	// because it is not the one verifying here. That is only safe because VerifyConnection below has already
	// checked the chain, the expiry window, enrolment and revocation — and it refuses the connection outright
	// if any of that fails, so a request can never reach this handler with an unchecked certificate.
	registerEnrollRenewEndpointWithIdentity(mux, cfg.Signer, cfg.Ledger, cfg.Tenant, cfg.CertTTL,
		func(r *http.Request) (string, bool) {
			if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				return "", false
			}
			return transportIdentityFromLeaf(r.TLS.PeerCertificates[0]), true
		}, log.Printf)

	return mux
}

// enrollRenewGraceVerify is the whole check Go is not doing: chain, expiry window, enrolment and revocation.
// Shared for the same reason the mux is — two copies of this would be two different definitions of who may
// recover.
func enrollRenewGraceVerify(cfg enrollRenewGraceConfig, pool *x509.CertPool) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			log.Printf("enroll_renew_grace_denied reason=no_client_cert")
			return fmt.Errorf("renewal recovery: no client certificate")
		}
		// Trust exactly what the (T) transport trusts RIGHT NOW. The pool built at start-up goes stale
		// both ways once the runtime-mutable store changes it: a CA added there would be refused here (a
		// device whose renewed certificate expired while switched off could never recover), and a CA
		// retired there would still be accepted here. Falling back to the start-up pool keeps store-less
		// deployments working.
		trusted := pool
		if p := transportClientCAPool.Load(); p != nil {
			trusted = p
		}
		// A shared Edge serves several organizations. Bind a named recovery
		// handshake to the server-owned name index, then verify the issuing CA
		// and the enrolled record against that same organization.
		connectionConfig := cfg
		namedOrganization := ""
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(cs.ServerName)), recoveryNamePrefix) {
			if _, tenant, ok := transportTenantCertificates.For(cs.ServerName); ok {
				if cfg.TenantRegistry == nil || strings.TrimSpace(tenant) == "" {
					return fmt.Errorf("renewal recovery: named organization has no issuer registry")
				}
				namedOrganization = tenant
				connectionConfig.Tenant = tenant
			}
		}
		identity, err := verifyRecoveringClient(cs.PeerCertificates[0], cs.PeerCertificates[1:], trusted, connectionConfig, time.Now())
		if err != nil {
			log.Printf("enroll_renew_grace_denied reason=%q", err.Error())
			return fmt.Errorf("renewal recovery: %w", err)
		}
		if namedOrganization != "" && !strings.EqualFold(renewTenantOf(cfg.Ledger, identity), namedOrganization) {
			return fmt.Errorf("renewal recovery: enrolled identity does not belong to the named organization")
		}
		// Security-relevant on the happy path too: a device returning with a credential that has been dead
		// for weeks is something an operator should see individually, not discover in aggregate later.
		log.Printf("enroll_renew_grace_admitted identity=%q expired_ago=%s window=%s — a device is recovering "+
			"from an expired certificate; it can renew and NOTHING else on this listener",
			identity, time.Since(cs.PeerCertificates[0].NotAfter).Round(time.Hour), cfg.Window)
		return nil
	}
}

func startEnrollRenewGraceServer(cfg enrollRenewGraceConfig, mux *http.ServeMux, tlsCfg *tls.Config) error {
	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() {
		log.Printf("enroll renewal RECOVERY listener on %s (expired certificates accepted up to %s past expiry, "+
			"for enrolled and non-revoked identities, and ONLY for POST /enroll/renew)", cfg.Listen, cfg.Window)
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			// Not fatal: losing the recovery path degrades long-absence handling but must not take the Edge
			// down. It is logged loudly because nothing else would reveal its absence until a device needed it.
			log.Printf("enroll renewal RECOVERY listener stopped: %v — devices whose certificate expires while "+
				"switched off will need manual re-enrolment until this is restored", err)
		}
	}()
	return nil
}
