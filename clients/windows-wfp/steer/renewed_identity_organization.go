package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"strings"
)

// A renewal pointer survives provisioning and may belong to the previous
// organization. It must not override the identity just issued by enrollment.
// The caller retains all pointer files and keys for explicit rollback.
func renewedIdentityBelongsToEnrollment(renewed *tls.Certificate, enrollmentPEM []byte) bool {
	if len(enrollmentPEM) == 0 {
		return true
	} // Legacy file-based identity path.
	block, _ := pem.Decode(enrollmentPEM)
	if block == nil {
		return false
	}
	enrolled, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	organization := func(c *x509.Certificate) string {
		for _, value := range c.Subject.Organization {
			if value = strings.TrimSpace(value); value != "" {
				return strings.ToLower(value)
			}
		}
		return ""
	}
	tenant := organization(enrolled)
	if tenant == "" {
		return true
	} // Preserve legacy enrollment without a tenant claim.
	if renewed == nil || len(renewed.Certificate) == 0 {
		return false
	}
	candidate, err := x509.ParseCertificate(renewed.Certificate[0])
	return err == nil && organization(candidate) == tenant
}
