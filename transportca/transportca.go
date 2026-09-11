// Package transportca introduces a CA layer under the endpoint↔Edge transport certificate, and rotates that CA
// WITHOUT invalidating the anchors devices already pinned.
//
// Why it exists. The transport certificate started life self-signed and CA:TRUE, and devices pin that single
// certificate as their trust anchor. So the leaf and the anchor are the same object: re-minting the server
// certificate — to add a SAN, to extend validity, to move hosts — silently invalidates every device's pin. That
// has already caused outages, and a device that is switched off while it happens cannot be repaired remotely,
// because the channel it would be repaired over is the one that just broke.
//
// The fix is the ordinary PKI shape: a long-lived CA is the anchor, and the server certificate is a short-lived
// leaf beneath it. Re-minting the leaf then touches nothing a device pinned.
//
// Migrating there is itself the hard part — every device is pinned to the OLD certificate — and CrossSign is
// what makes it non-breaking. The old self-signed certificate is CA:TRUE with Certificate Sign, so it can issue
// a cross-certificate for the new CA: the new CA's own name and key, signed by the old anchor. Serving
// leaf + cross-certificate lets a device holding EITHER anchor build a path:
//
//	old-anchor device:  leaf → cross-cert (new CA, issued by old anchor) → old anchor  ✓
//	new-anchor device:  leaf → new CA                                                   ✓
//
// The same construction rotates one CA to the next later on. Because both anchors validate for as long as the
// cross-certificate is served, the overlap can be made longer than the longest expected shutdown, and the
// deadlock never forms. The old private key is only needed to MINT the cross-certificate; once it exists the
// old key can be destroyed and the signature keeps working.
package transportca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// serialNumber draws a random 128-bit serial. Certificates minted here may be re-issued for the same subject
// (a rotation mints a new CA with the same name as its predecessor is replaced), so serials must not collide.
func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("transport CA serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// CA is a transport CA: the certificate devices pin, plus the key that signs leaves beneath it.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// NewCA mints a self-signed transport CA. Give it a validity longer than the longest shutdown you intend to
// survive plus the rotation overlap — this certificate is what devices pin, so its expiry is a fleet-wide
// deadline, not a maintenance detail.
func NewCA(subject pkix.Name, key crypto.Signer, notBefore, notAfter time.Time) (*CA, error) {
	if key == nil {
		return nil, fmt.Errorf("transport CA needs a signing key")
	}
	if !notBefore.Before(notAfter) {
		return nil, fmt.Errorf("transport CA validity is empty (notBefore %s not before notAfter %s)", notBefore, notAfter)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		// pathLen 1, not 0. This CA issues leaves directly, so 0 looks right — but a rotation puts the NEXT CA's
		// cross-certificate between this anchor and the leaf, and pathLen 0 forbids exactly that. A device
		// pinned here would then reject the very chain the rotation depends on, and it would fail only for the
		// devices that had not yet moved: invisible to whoever performs it. Caught by
		// TestRotatingTheCAKeepsThePreviousAnchorValid.
		MaxPathLen: 1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create transport CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse transport CA: %w", err)
	}
	return &CA{Cert: cert, Key: key}, nil
}

// CrossSign issues a cross-certificate for subordinate's certificate under issuer: the SAME subject and public
// key, signed by the issuer instead of by itself. A device that trusts the issuer can therefore build a path to
// anything the subordinate issued, without ever being told about the subordinate.
//
// notAfter bounds the overlap window. It is capped at the issuer's own expiry — a cross-certificate outliving
// its issuer would validate for nobody and would quietly mislead an operator into thinking the overlap was
// longer than it is.
//
// The issuer here may be the OLD self-signed transport certificate (it is CA:TRUE with Certificate Sign), which
// is what allows the first migration onto a real CA layer to happen without breaking a single pinned device.
func CrossSign(issuerCert *x509.Certificate, issuerKey crypto.Signer, subordinate *x509.Certificate, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	if issuerCert == nil || issuerKey == nil || subordinate == nil {
		return nil, fmt.Errorf("cross-sign needs an issuer certificate, an issuer key and a subordinate")
	}
	if !issuerCert.IsCA {
		return nil, fmt.Errorf("cross-sign issuer %q is not a CA", issuerCert.Subject.CommonName)
	}
	if issuerCert.KeyUsage != 0 && issuerCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("cross-sign issuer %q may not sign certificates", issuerCert.Subject.CommonName)
	}
	if !subordinate.IsCA {
		return nil, fmt.Errorf("cross-sign subordinate %q is not a CA", subordinate.Subject.CommonName)
	}
	if notAfter.After(issuerCert.NotAfter) {
		// Silently shortening is safer than issuing a promise the issuer cannot keep.
		notAfter = issuerCert.NotAfter
	}
	if !notBefore.Before(notAfter) {
		return nil, fmt.Errorf("cross-certificate validity is empty (issuer expires %s)", issuerCert.NotAfter)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subordinate.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              subordinate.KeyUsage,
		BasicConstraintsValid: true,
		// Mirror the subordinate's own path-length budget rather than imposing a tighter one: the
		// cross-certificate stands in for that CA, so anything it could issue on its own it must still be able
		// to issue through this path — including the cross-certificate of a LATER rotation.
		MaxPathLen:     subordinate.MaxPathLen,
		MaxPathLenZero: subordinate.MaxPathLenZero,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, subordinate.PublicKey, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("create cross-certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse cross-certificate: %w", err)
	}
	return cert, nil
}

// LeafRequest describes the transport server certificate to mint beneath a CA.
type LeafRequest struct {
	Subject   pkix.Name
	DNSNames  []string
	IPs       []net.IP
	NotBefore time.Time
	NotAfter  time.Time
}

// IssueServerLeaf mints the transport server certificate. This is the certificate the Edge presents and the one
// that may now be re-minted freely: it is not anyone's anchor.
func (ca *CA) IssueServerLeaf(key crypto.Signer, req LeafRequest) (*x509.Certificate, error) {
	if ca == nil || ca.Cert == nil || ca.Key == nil {
		return nil, fmt.Errorf("transport CA is not initialised")
	}
	if key == nil {
		return nil, fmt.Errorf("server leaf needs a key")
	}
	if len(req.DNSNames) == 0 && len(req.IPs) == 0 {
		// A transport certificate with no SAN matches no host; every client would reject it.
		return nil, fmt.Errorf("server leaf needs at least one DNS name or IP address")
	}
	if !req.NotBefore.Before(req.NotAfter) {
		return nil, fmt.Errorf("server leaf validity is empty")
	}
	if req.NotAfter.After(ca.Cert.NotAfter) {
		return nil, fmt.Errorf("server leaf would outlive its CA (CA expires %s)", ca.Cert.NotAfter)
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               req.Subject,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPs,
		NotBefore:             req.NotBefore,
		NotAfter:              req.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, fmt.Errorf("create transport server leaf: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse transport server leaf: %w", err)
	}
	return cert, nil
}

// ChainPEM builds the PEM the Edge serves: the leaf first, then any intermediates. During a migration or
// rotation the cross-certificate goes here — that is the entire mechanism by which a device pinned to the OLD
// anchor can still build a path. Serving only the leaf works for new-anchor devices and strands every old one.
func ChainPEM(leaf *x509.Certificate, intermediates ...*x509.Certificate) ([]byte, error) {
	if leaf == nil {
		return nil, fmt.Errorf("chain needs a leaf")
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	for _, c := range intermediates {
		if c == nil {
			continue
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out, nil
}

// AnchorsPEM concatenates the certificates a device should pin. Devices pin a LIST precisely so a rotation can
// hand them the next anchor before the old one is withdrawn.
func AnchorsPEM(anchors ...*x509.Certificate) ([]byte, error) {
	if len(anchors) == 0 {
		return nil, fmt.Errorf("no anchors to encode")
	}
	var out []byte
	for _, c := range anchors {
		if c == nil {
			continue
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no anchors to encode")
	}
	return out, nil
}
