package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Refusing a certificate the fleet would refuse.
//
// On 2026-07-31 a hand-minted transport leaf was accepted here and stranded every device for 47 minutes:
// it was valid, in date, and its key matched — the only things this path checked — but it had no
// basicConstraints, so the endpoints' platform verifier rejected it. The failure surfaced 24 minutes later,
// when an Edge restart forced the agents to re-handshake, because a hot reload only changes what NEW
// connections see. docs/2026-07-31_edge_identity_certificate_replacement_outage.ja.md.
//
// So the acceptance test is: would a DEVICE accept this? Two parts, both stated as named failures.
//
//   1. Path: the candidate must chain to a certificate the fleet is currently distributed and told to trust.
//      Checked with the chain the Edge would actually present as intermediates — the same material, the same
//      direction, as the device.
//   2. Shape: the leaf hygiene platform verifiers require. basicConstraints CA:FALSE is the one that bit us;
//      the rest are here because the next hand-minted certificate will miss a different one.
//
// SAN coverage is checked against the addresses agents are told to dial, not against a guess: a chain that
// verifies and does not cover the name is exactly as fatal, and its error mentions no names at all.

type certAdmissionInput struct {
	// Leaf and Chain are the candidate as it would be served (Chain excludes the leaf).
	Leaf  *x509.Certificate
	Chain []*x509.Certificate
	// TrustedPEM is what the fleet is currently told to trust — the live distribution, never a file that
	// may have drifted from it.
	TrustedPEM string
	// DialNames are the hosts agents actually connect to (region endpoints, the published transport URL).
	DialNames []string
	// AdoptedByEveryDevicePEM is the subset of the distribution that EVERY enrolled device is reported to
	// hold, and NotYetAdoptedBy names the devices holding the rest back. Empty means adoption cannot be
	// measured here, in which case the distribution check above stands alone and says so by staying silent
	// rather than inventing certainty.
	AdoptedByEveryDevicePEM []string
	NotYetAdoptedBy         []string
}

// verifyCertificateWouldBeAcceptedByDevices returns nil when a device would accept this certificate, or an
// error naming what is missing. Errors are written for the operator pasting the certificate.
func verifyCertificateWouldBeAcceptedByDevices(in certAdmissionInput) error {
	if in.Leaf == nil {
		return fmt.Errorf("no certificate")
	}

	if err := verifyCertificateShape(in.Leaf); err != nil {
		return err
	}

	// 2. SAN coverage of what agents dial. Named, so the operator can see which address is uncovered.
	// With no dial names configured this used to iterate zero times and pass in silence — half the failure
	// class this file exists for, degrading to nothing rather than saying so (review R8).
	if len(in.DialNames) == 0 {
		return fmt.Errorf("this node does not know which addresses agents connect to (-network-extension-transport-tls-url / -region-endpoints), so it cannot check the certificate covers them")
	}
	for _, name := range in.DialNames {
		host := strings.TrimSpace(name)
		if host == "" {
			continue
		}
		if err := in.Leaf.VerifyHostname(host); err != nil {
			return fmt.Errorf("the certificate does not cover %q, which agents are told to connect to — they would refuse it with an error that never mentions names", host)
		}
	}

	// 3. Path to what the fleet trusts. Skipping this when nothing is distributed would leave the shape
	// checks alone standing in for the question this file exists to answer.
	if strings.TrimSpace(in.TrustedPEM) == "" {
		return fmt.Errorf("no trust distribution is configured on this node, so whether devices could verify this certificate cannot be established")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(in.TrustedPEM)) {
		return fmt.Errorf("the current trust distribution could not be parsed, so acceptance cannot be checked")
	}
	inter := x509.NewCertPool()
	for _, c := range in.Chain {
		inter.AddCert(c)
	}
	if _, err := in.Leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("no certificate the fleet currently trusts can verify this one (%v) — distribute the issuing certificate to devices FIRST, wait until they hold it, then replace", err)
	}

	// 4. DISTRIBUTED is not ADOPTED. A certificate that verifies only against material added minutes ago
	// passes the check above and strands every device that has not taken the new distribution yet — the
	// same shape of failure as the outage, arriving on the next handshake rather than immediately. So the
	// path is re-checked against the certificates devices are actually REPORTED to hold; a certificate
	// that survives only on the newest one is refused, naming the devices it would strand (review R8①).
	if len(in.AdoptedByEveryDevicePEM) > 0 {
		adopted := x509.NewCertPool()
		if adopted.AppendCertsFromPEM([]byte(strings.Join(in.AdoptedByEveryDevicePEM, "\n"))) {
			if _, err := in.Leaf.Verify(x509.VerifyOptions{
				Roots: adopted, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				return fmt.Errorf("only a certificate the fleet has NOT finished adopting can verify this one — %s would be stranded at their next handshake; wait for adoption to complete, then replace",
					strings.Join(in.NotYetAdoptedBy, ", "))
			}
		}
	}
	return nil
}

// verifyCertificateShape is the leaf hygiene every platform verifier applies, whoever the peer is. Each
// item here is a way a certificate can be valid, in date, key-matched — and rejected on the device.
func verifyCertificateShape(leaf *x509.Certificate) error {
	if !leaf.BasicConstraintsValid {
		return fmt.Errorf("the certificate has no basicConstraints extension — endpoints reject a server certificate that does not declare CA:FALSE. Re-issue with basicConstraints=critical,CA:FALSE (openssl x509 -req does NOT copy extensions; they must be given in -extfile)")
	}
	if leaf.IsCA {
		return fmt.Errorf("this is a CA certificate (basicConstraints CA:TRUE) — a server certificate must be an end-entity certificate")
	}
	// keyUsage and extendedKeyUsage are REQUIRED, not merely consistent-if-present. The first version
	// skipped both when absent, so two of the three defects in the certificate that stranded the fleet
	// would still have been accepted (review C4).
	if leaf.KeyUsage == 0 {
		return fmt.Errorf("the certificate has no keyUsage extension — a TLS server certificate declares digitalSignature")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("the certificate's keyUsage does not include digitalSignature, which a TLS server certificate needs")
	}
	if len(leaf.ExtKeyUsage) == 0 && len(leaf.UnknownExtKeyUsage) == 0 {
		return fmt.Errorf("the certificate has no extendedKeyUsage — endpoints require serverAuth on a TLS server certificate")
	}
	serverAuth := false
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			serverAuth = true
		}
	}
	if !serverAuth {
		return fmt.Errorf("the certificate's extendedKeyUsage does not include serverAuth")
	}
	// Apple caps a TLS server certificate at 398 days and rejects weak keys outright; a certificate the
	// path check accepts can still be refused on the device for either.
	if life := leaf.NotAfter.Sub(leaf.NotBefore); life > 398*24*time.Hour {
		return fmt.Errorf("the certificate is valid for %d days — endpoints reject a TLS server certificate valid for more than 398", int(life.Hours()/24))
	}
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return fmt.Errorf("the certificate's RSA key is %d bits — endpoints require at least 2048", pub.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if pub.Curve.Params().BitSize < 256 {
			return fmt.Errorf("the certificate's EC key is %d bits — endpoints require at least P-256", pub.Curve.Params().BitSize)
		}
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return fmt.Errorf("the certificate carries no subjectAltName — endpoints match the address they dialled against SAN, never against the subject")
	}

	return nil
}

// guardServedCertificateChange is the ONE place a change to served material is admitted. Both the admin
// replace and the ROLLBACK go through it: rollback reaches back to material that was acceptable when it
// was stored, and acceptability is relative to the trust distribution of the moment — an anchor withdrawn
// since means no device can verify that certificate today. The 2026-07-31 outage certificate is itself a
// stored version, so an unguarded rollback re-creates the outage on request.
//
// Named for what it guards rather than for the check it runs, because the next path that changes served
// material must call this, not re-implement it. (Not covered: SIGHUP reload and a direct file write —
// those require filesystem access to the node, a different trust model, and are called out in the
// review ledger rather than pretended away.)
func guardServedCertificateChange(config serverConfig, name, certPEM string) error {
	// Which certificates does this apply to? The one devices verify, always. Everything else this node
	// serves is verified by the Console, connectors and the control plane — peers that pin it just as
	// hard — so the shape checks apply there too; only the path-to-the-fleet question is specific to the
	// transport certificate (review C5: the guard was wired to exactly one name).
	devicesVerifyIt := strings.TrimSpace(config.TransportCertFile) != "" && name == deriveCertName(config.TransportCertFile)
	candidate := parseAllCerts([]byte(certPEM))
	if len(candidate) == 0 {
		return fmt.Errorf("no certificate found")
	}
	if !devicesVerifyIt {
		// A management certificate: the platform requirements still apply to whoever verifies it, but this
		// node has no trust distribution or dial-name list to judge it against.
		if err := verifyCertificateShape(candidate[0]); err != nil {
			return fmt.Errorf("peers would refuse this certificate: %w", err)
		}
		return nil
	}
	trustedPEM, _ := currentTrustAnchors(config)
	adoptedPEM, notYet := fullyAdoptedTrust(config)
	if err := verifyCertificateWouldBeAcceptedByDevices(certAdmissionInput{
		Leaf: candidate[0], Chain: candidate[1:], TrustedPEM: trustedPEM,
		DialNames:               transportDialNames(config, config.RegionEndpointURLs),
		AdoptedByEveryDevicePEM: adoptedPEM, NotYetAdoptedBy: notYet,
	}); err != nil {
		return fmt.Errorf("devices would refuse this certificate: %w", err)
	}
	return nil
}

// transportDialNames are the hosts agents are told to connect to, from this deployment's own configuration.
func transportDialNames(config serverConfig, regionEndpoints []string) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(raw string) {
		h := strings.TrimSpace(raw)
		if h == "" {
			return
		}
		h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
		if i := strings.IndexAny(h, "/"); i >= 0 {
			h = h[:i]
		}
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	add(config.TransportTLSURL)
	for _, e := range regionEndpoints {
		add(e)
	}
	return out
}

// regionEndpointHostsFrom parses the "region=URL;region=URL" map into its URLs. Parsing failures yield
// nothing rather than an error: this feeds a SAN-coverage check, and a malformed map must not block a
// replacement it cannot speak about.
func regionEndpointHostsFrom(spec string) []string {
	out := []string{}
	for _, pair := range strings.Split(spec, ";") {
		if i := strings.Index(pair, "="); i >= 0 {
			if u := strings.TrimSpace(pair[i+1:]); u != "" {
				out = append(out, u)
			}
		}
	}
	return out
}

// fullyAdoptedTrust splits the distribution into the certificates EVERY enrolled device is reported to
// hold, and the devices that are holding the rest back. Returns nothing when adoption cannot be measured
// — a node with no telemetry has no business claiming a certificate is safe to switch to.
func fullyAdoptedTrust(config serverConfig) (adopted []string, notYet []string) {
	if config.ObservedExclusions == nil {
		return nil, nil
	}
	pems, _ := currentTrustAnchors(config)
	certs := parseAllCerts([]byte(pems))
	if len(certs) == 0 {
		return nil, nil
	}
	known := enabledEnrolledIdentities(config)
	if len(known) == 0 {
		return nil, nil
	}
	pending := map[string]bool{}
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		cov := anchorCoverage(config, config.TenantIDForTrust, hex.EncodeToString(sum[:]), known)
		if cov.SafeToCut {
			adopted = append(adopted, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
			continue
		}
		for _, id := range append(append(append([]string{}, cov.NotReady...), cov.Silent...), cov.NeverReportedAnything...) {
			pending[id] = true
		}
	}
	for id := range pending {
		notYet = append(notYet, id)
	}
	sort.Strings(notYet)
	return adopted, notYet
}
