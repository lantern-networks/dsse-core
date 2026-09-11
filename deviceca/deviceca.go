// Package deviceca is the device-identity CA signer used by the Control Plane to issue short-lived device
// client certificates at enrollment. It signs a device CSR into a leaf cert (ExtKeyUsage=ClientAuth) chained
// to the device CA the endpoint agent then pins.
//
// This is the software CA signer; in production the CA private key SHOULD live in an HSM/KMS (e.g. a managed
// private-CA or KMS service). NewSigner accepts any crypto.Signer so an HSM-backed key drops in without
// changing this package. Short TTLs + automated re-issuance are what replace the manual device.crt re-mint.
package deviceca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// NewSigner builds a signer from an already-parsed CA cert + key (in-memory or HSM-backed crypto.Signer).
func NewSigner(caCert *x509.Certificate, caKey crypto.Signer) *Signer {
	return &Signer{
		caCert: caCert,
		caKey:  caKey,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}),
	}
}

// LoadSigner loads the device CA cert (PEM) and private key (PEM: EC or PKCS8) from disk.
func LoadSigner(certPath, keyPath string) (*Signer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("deviceca: read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("deviceca: read key: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, errors.New("deviceca: no PEM certificate")
	}
	caCert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("deviceca: parse cert: %w", err)
	}
	if !caCert.IsCA {
		return nil, errors.New("deviceca: certificate is not a CA")
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("deviceca: no PEM key")
	}
	key, err := parsePrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return NewSigner(caCert, key), nil
}

// CAPEM returns the PEM of the device CA certificate (returned to the agent to pin).
func (s *Signer) CAPEM() []byte { return s.caPEM }

// NameSpaceSuffix, when set, gives every issued device certificate a DNS SAN of
// "<common-name>.<NameSpaceSuffix>" — a name inside a namespace a per-tenant intermediate can be CONSTRAINED
// to. Without one, device certificates carry a bare CN and no constrainable name at all, so a name-constrained
// intermediate cannot verify them: that is precisely what rejected two renewals on 2026-08-02 and forced the
// constraint to be withdrawn.
//
// The COMMON NAME is left alone on purpose. Agents match the issued certificate's CN against the device id
// they asked for and refuse a mismatch (Windows validateIssued, and the identity taken from the CN in
// heartbeats) — so moving the identity into an FQDN is an endpoint change on both platforms, while ADDING a
// SAN is not — a split the endpoint and CA sides agreed on and both keep to.
//
// Empty (the default) issues exactly what it issued before.
type Signer struct {
	caCert          *x509.Certificate
	caKey           crypto.Signer
	caPEM           []byte
	NameSpaceSuffix string
}

// Sign signs a device CSR (PEM) into a leaf client cert valid for ttl. The CSR is used ONLY for its public key
// + proof-of-possession (its self-signature is verified); the cert's SUBJECT is the CP-AUTHORITATIVE `subject`
// the caller supplies (device id / assigned tenant / group), NOT the device-controlled CSR subject — so a device
// cannot mint a cert impersonating another device or tenant. Leaf is ClientAuth, CA:FALSE, random 128-bit serial.
func (s *Signer) Sign(csrPEM []byte, subject pkix.Name, ttl time.Duration) (certPEM []byte, err error) {
	cb, _ := pem.Decode(csrPEM)
	if cb == nil {
		return nil, errors.New("deviceca: no PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("deviceca: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("deviceca: csr self-signature invalid: %w", err)
	}
	if subject.CommonName == "" {
		return nil, errors.New("deviceca: authoritative subject CommonName required")
	}
	if ttl <= 0 {
		ttl = 60 * 24 * time.Hour
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	leaf := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject, // CP-authoritative — the CSR's own Subject is deliberately ignored
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, // stamp CA:FALSE explicitly (client leaf)
		IsCA:                  false,
	}
	// A name inside the tenant's namespace, so a constrained intermediate has something to permit. Derived
	// from the authoritative CN rather than anything the CSR asked for — the whole point of ignoring the CSR
	// subject would be lost if the device could choose the name the constraint is checked against.
	if suffix := strings.Trim(strings.TrimSpace(s.NameSpaceSuffix), "."); suffix != "" {
		leaf.DNSNames = []string{strings.ToLower(subject.CommonName) + "." + strings.ToLower(suffix)}
	}
	var der []byte
	if minter, ok := s.caKey.(certMinter); ok {
		// Mint through the sidecar's PURPOSE-BOUND /sign-cert, so the agent — not this process — fixes
		// CA:FALSE / clientAuth and bounds the validity. A compromised issuer holding the device-CA token cannot
		// turn the key into a CA or a server-auth minter; it can only produce the device-leaf shape.
		der, err = minter.SignCert(leaf, s.caCert, csr.PublicKey, "device-leaf")
	} else {
		der, err = x509.CreateCertificate(rand.Reader, leaf, s.caCert, csr.PublicKey, s.caKey)
	}
	if err != nil {
		return nil, fmt.Errorf("deviceca: sign: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// certMinter is a caKey that can mint a purpose-bound leaf through an HSM sidecar's /sign-cert,
// instead of having this process build the certificate and hand the key only a digest. The Edge's HSM signer
// implements it; an in-process key does not, and Sign then builds the certificate locally exactly as before.
type certMinter interface {
	SignCert(template, issuer *x509.Certificate, leafPub crypto.PublicKey, purpose string) ([]byte, error)
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("deviceca: PKCS8 key is not a signer")
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("deviceca: unsupported private key format")
}
