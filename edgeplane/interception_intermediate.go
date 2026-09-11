package edgeplane

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"sync"
	"time"
)

// InterceptionIssuer is what actually SIGNS per-SNI leaves, plus the chain to present after the leaf. Without an
// intermediate it IS the root (chain = [root]) — today's behavior. With an intermediate (Slice 3 of
// docs/pki_trust_model.md) it is a rotatable intermediate signed by the root (chain = [intermediate, root]), so:
//   - the ROOT key signs only intermediates and can stay OFFLINE / in an HSM — the per-leaf signer (the exposed,
//     online key) is the intermediate, not the crown-jewel root;
//   - the intermediate can be ROTATED without re-distributing trust: devices still anchor on the same root, the
//     leaf path just chains through a fresh intermediate (no flag day, no MDM re-push);
//   - the intermediate can carry Name Constraints, so a leaked intermediate mints leaves only for the permitted
//     name space (meaningful when interception is scoped to a finite host set; left unconstrained under
//     decrypt-all, where the permitted set is effectively everything).
type InterceptionIssuer struct {
	trustAnchor *x509.Certificate // Validity matters even when the anchor is omitted from the wire chain.
	signingCert *x509.Certificate
	signer      crypto.Signer
	chain       [][]byte // DER certs appended AFTER the leaf, signing cert first: [root] or [intermediate, root]

	// The validity window of the whole PRESENTED path, computed once. See usableAt.
	pathOnce  sync.Once
	pathFrom  time.Time
	pathUntil time.Time
	pathErr   error
}

// usableAt reports whether every certificate this issuer PRESENTS is inside its own validity at `at`.
//
// ★★★ THE SIGNING CERTIFICATE IS ONE LINK, AND A CLIENT VERIFIES ALL OF THEM (2026-09-08, found by review).
//
// The freshness check compared the cached leaf's issuer and asked THAT certificate about its expiry. A
// per-Edge issuing CA sits under an operator issuing CA under the organization's root, and the tier above
// the one doing the signing can end first. Reproduced: root -> CP issuer (one minute left) -> Edge issuer
// (valid) -> leaf. Everything verified at load. Two minutes later the same cached leaf came back, and a
// client-side full-path verify refused it — the Edge could not see it, because it had only ever looked at
// the link it signed with.
//
// The window is the INTERSECTION: the latest NotBefore and the earliest NotAfter across the path. That is
// the interval in which what this node hands a client can actually be verified, which is the only interval
// worth calling usable.
func (i *InterceptionIssuer) usableAt(at time.Time) error {
	if i == nil {
		return fmt.Errorf("no interception issuer")
	}
	i.pathOnce.Do(func() {
		if i.signingCert == nil {
			i.pathErr = fmt.Errorf("the issuer holds no signing certificate")
			return
		}
		i.pathFrom, i.pathUntil = i.signingCert.NotBefore, i.signingCert.NotAfter
		if root := i.trustAnchor; root != nil {
			if root.NotBefore.After(i.pathFrom) {
				i.pathFrom = root.NotBefore
			}
			if root.NotAfter.Before(i.pathUntil) {
				i.pathUntil = root.NotAfter
			}
		}
		for n, der := range i.chain {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				i.pathErr = fmt.Errorf("parse certificate %d of the presented chain: %w", n, err)
				return
			}
			if c.NotBefore.After(i.pathFrom) {
				i.pathFrom = c.NotBefore
			}
			if c.NotAfter.Before(i.pathUntil) {
				i.pathUntil = c.NotAfter
			}
		}
	})
	if i.pathErr != nil {
		return i.pathErr
	}
	if at.Before(i.pathFrom) {
		return fmt.Errorf("the chain this node would present is not valid until %s (asked at %s)",
			i.pathFrom.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339))
	}
	if !at.Before(i.pathUntil) {
		return fmt.Errorf("a certificate in the chain this node would present expired at %s (asked at %s) — "+
			"every client verifies the whole path, so signing under it produces a certificate they refuse",
			i.pathUntil.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339))
	}
	return nil
}

// directInterceptionIssuer signs leaves with the root directly (chain = [root]). This is the default and is
// byte-for-byte today's behavior.
func directInterceptionIssuer(provider InterceptionRootProvider) *InterceptionIssuer {
	return &InterceptionIssuer{
		trustAnchor: provider.Certificate(),
		signingCert: provider.Certificate(),
		signer:      provider.Signer(),
		chain:       [][]byte{provider.Certificate().Raw},
	}
}

// newIntermediateInterceptionIssuer generates a fresh rotatable intermediate CA signed by the provider's root
// (with optional permitted-DNS name constraints) and returns it as the leaf issuer (chain = [intermediate, root]).
// The root must allow a path length >= 1 (the interception root is created with MaxPathLen 1).
func newIntermediateInterceptionIssuer(provider InterceptionRootProvider, permittedDNS []string, now func() time.Time) (*InterceptionIssuer, error) {
	if provider == nil || provider.Certificate() == nil || provider.Signer() == nil {
		return nil, fmt.Errorf("interception intermediate: root provider is incomplete")
	}
	if now == nil {
		now = time.Now
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate interception intermediate key: %w", err)
	}
	serial, err := RandomNetworkExtensionLabTLSSerial()
	if err != nil {
		return nil, err
	}
	createdAt := now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   NetworkExtensionLabTLSRootCommonName + " Issuing CA",
			Organization: []string{NetworkExtensionLabTLSLeafOrganization},
		},
		// Backdated an HOUR, not a minute.
		//
		// A minute was not enough. This is the INTERMEDIATE: every interception leaf chains through it, so a
		// client whose clock is even slightly ahead rejects the whole chain and loses ALL interception, not one
		// site. A machine that has just booted and not yet reached an NTP server is routinely off by more than a
		// minute, so the failure is ordinary rather than exotic — and it presents as "certificate not yet valid"
		// on every site at once, which reads like a CA problem rather than a clock one.
		//
		// An hour matches what the root (interception_hsm_agent.go) and the leaves (oss/interception) already
		// use; a minute here was the odd one out. The cost of backdating further is that a compromised
		// intermediate is usable for an extra hour BEFORE it was issued, which is not a meaningful window when
		// its total validity is measured in months.
		NotBefore:             createdAt.Add(-time.Hour),
		NotAfter:              createdAt.Add(NetworkExtensionLabTLSRootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	if len(permittedDNS) > 0 {
		// Constrain what this intermediate (and thus a leak of it) can mint leaves for. Critical so a verifier
		// that does not understand the extension rejects rather than ignores it.
		tmpl.PermittedDNSDomainsCritical = true
		tmpl.PermittedDNSDomains = append([]string(nil), permittedDNS...)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, provider.Certificate(), &key.PublicKey, provider.Signer())
	if err != nil {
		return nil, fmt.Errorf("create interception intermediate: %w", err)
	}
	inter, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse interception intermediate: %w", err)
	}
	return &InterceptionIssuer{
		trustAnchor: provider.Certificate(),
		signingCert: inter,
		signer:      key,
		// ★★ THE ANCHOR IS NOT PRESENTED — see loadOfflineInterceptionIssuer. provider.Certificate() is the
		// root here; a device trusts it from its own store, and sending it back made a four-deep chain that
		// git reports as "self signed certificate in certificate chain".
		chain: interceptionChainWithoutTheAnchor(inter, provider.Certificate()),
	}, nil
}
