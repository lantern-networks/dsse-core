package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"
)

// deviceCAIsReparentOf reports whether replacement is the SAME certification authority as previous, re-issued
// under a different parent.
//
// ★ WHY THIS DISTINCTION HAS TO EXIST (2026-08-19, hit live). Moving an organization's device CA out of the
// provider's PKI tree and under the organization's own root is done by re-issuing the CA's OWN certificate
// with the same subject and the same key, signed by the new root. Every device certificate that verified
// under the old one verifies under the new one: a leaf chains by ISSUER NAME, and its signature is checked
// with the CA's PUBLIC KEY, and both are unchanged. Nobody can be locked out by withdrawing the old one.
//
// The withdrawal gate could not see that. It compared fingerprints, saw two unrelated CAs, and refused while
// naming every device still admitted — a refusal that is right for a rotation and impossible for a re-parent.
// Without this an organization can only leave the provider's tree by re-issuing every device certificate
// first, which is the one thing a re-parent exists to avoid.
//
// Both halves are required and neither is cosmetic:
//
//	subject   a leaf naming the old issuer cannot chain to a certificate with a different subject at all,
//	          so a renamed CA is a different CA to every device holding a certificate from the old one.
//	key       a same-named CA with a NEW key is a real rotation: every signature made by the old key stops
//	          verifying. That is exactly the lockout the gate exists to prevent.
func deviceCAIsReparentOf(replacement, previous *x509.Certificate) bool {
	if replacement == nil || previous == nil {
		return false
	}
	// RawSubject / RawSubjectPublicKeyInfo rather than the parsed forms: what a verifier compares is the
	// encoded bytes, and two subjects that print the same can encode differently.
	if !bytes.Equal(replacement.RawSubject, previous.RawSubject) {
		return false
	}
	return bytes.Equal(replacement.RawSubjectPublicKeyInfo, previous.RawSubjectPublicKeyInfo)
}

// deviceCAReparentedBy returns the certificate among candidates that is a re-parent of previous, if any.
func deviceCAReparentedBy(previous *x509.Certificate, candidates []*x509.Certificate) (*x509.Certificate, bool) {
	for _, candidate := range candidates {
		if candidate == previous {
			continue
		}
		if deviceCAIsReparentOf(candidate, previous) {
			return candidate, true
		}
	}
	return nil, false
}

// deviceCACertificateByFingerprint returns the registered device CA with this SHA-256, or nil.
func deviceCACertificateByFingerprint(config serverConfig, sha256Hex string) *x509.Certificate {
	want := strings.ToLower(strings.TrimSpace(sha256Hex))
	if want == "" || config.TenantCARegistry == nil {
		return nil
	}
	for _, cert := range config.TenantCARegistry.Anchors() {
		if strings.EqualFold(certificateSHA256Hex(cert), want) {
			return cert
		}
	}
	return nil
}

// deviceCACertificatesForTenant returns the device CAs registered to one organization. The tenant is read
// from the registry rather than assumed, so a certificate registered to somebody else can never be offered as
// the replacement for this organization's.
func deviceCACertificatesForTenant(config serverConfig, tenant string) []*x509.Certificate {
	if config.TenantCARegistry == nil || strings.TrimSpace(tenant) == "" {
		return nil
	}
	wanted := map[string]bool{}
	for _, fact := range config.TenantCARegistry.Facts(time.Now()) {
		if strings.EqualFold(fact.TenantID, tenant) {
			wanted[strings.ToLower(strings.TrimSpace(fact.SHA256))] = true
		}
	}
	out := []*x509.Certificate{}
	for _, cert := range config.TenantCARegistry.Anchors() {
		if wanted[strings.ToLower(certificateSHA256Hex(cert))] {
			out = append(out, cert)
		}
	}
	return out
}

func certificateSHA256Hex(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
