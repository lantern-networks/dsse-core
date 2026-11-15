package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/lantern-networks/dsse-core/inspectioncrl"
	"math/big"
	"strings"
	"time"
)

// tenant_interception_authority_mint.go — giving an organization an interception authority of its own when it
// does not bring one.
//
// ★★★ THERE WAS NO WAY TO DO THIS (2026-08-30, found while standing a deployment up from nothing and
// confirmed from both platforms).
//
// The control plane holds every organization's interception authority — that is what
// -tenant-interception-authority-store is, and its own flag help says "Empty = this node hands Edges no
// interception material". Edges take it from there, so every Edge in the deployment signs an organization's
// traffic under the same root and its devices can be told one fingerprint.
//
// But POST /admin/tenant-interception-authority only IMPORTS. It is written for a customer who HAS a PKI:
// they sign an issuing CA under their own root and hand over root, certificate and key. An organization
// without a CA team — which is the ordinary onboarding case, and every lab — had no route at all. The only
// thing in the product that MINTED an interception root was the per-Edge one, which is per-Edge by
// construction:
//
//	osaka-edge-a signs Sakura Foods under  0a8fc598…
//	osaka-edge-b signs Sakura Foods under  5fe19463…
//	the door's trust bundle announces      d5e54171…
//
// So an organization had as many roots as the region had Edge processes, and which one signed a device's
// traffic depended on which process the door picked. Every step answered 200.
//
// This mints the pair the import path already knows how to check, and then goes THROUGH that path: one set of
// checks, one store, one shape in the database. What is minted is deliberately the same shape a customer would
// be asked to send — a self-signed root, and an issuing CA beneath it with room for one more CA — so a
// deployment that starts here and later moves to the customer's own PKI changes nothing else.

const (
	// A root the organization's devices install. Long, because replacing it means touching every device: the
	// overlap machinery exists (stage, announce, promote) and is still an operation somebody has to run.
	tenantInterceptionRootValidity = 5 * 365 * 24 * time.Hour
	// The issuing CA under it. Shorter than the root and longer than the per-Edge tier minted beneath it, so
	// the middle tier is the one that rotates without devices noticing.
	tenantInterceptionIssuingValidity = 2 * 365 * 24 * time.Hour
)

// mintTenantInterceptionAuthority makes a root and an issuing CA for one organization.
//
// displayName is what an operator will read in a certificate on a device — "Sakura Foods Interception Root",
// not a tenant id. ★ Roots that cannot be told apart by name are a defect this deployment already reports on
// (interceptionRootsIndistinguishableByName), and a fleet of organizations whose roots all read "Lantern DSSE
// Interception Root" is exactly that. The tenant id goes in the subject too, because display names are not
// unique and the id is.
func mintTenantInterceptionAuthority(tenant, displayName string, now time.Time) (rootPEM, issuingPEM, issuingKeyPEM string, err error) {
	rootPEM, issuingPEM, issuingKeyPEM, _, err = mintTenantInterceptionAuthorityPublishingAt(tenant, displayName, now, nil)
	return
}

// mintTenantInterceptionAuthorityPublishingAt is the same, for a deployment that publishes revocation lists
// at crlOrigins. The issuing certificate then names where its own status is published, and the root signs
// the one list it will ever sign — sealed, empty, valid for as long as the issuing certificate — before its
// key is dropped at the end of this function. With no origins nothing names a list and none is made.
func mintTenantInterceptionAuthorityPublishingAt(tenant, displayName string, now time.Time, crlOrigins []string) (rootPEM, issuingPEM, issuingKeyPEM string, sealedRootCRL []byte, err error) {
	rootPEM, issuingPEM, issuingKeyPEM, sealedRootCRL, err = mintTenantInterceptionAuthorityWith(tenant, displayName, now, crlOrigins)
	return
}

func mintTenantInterceptionAuthorityWith(tenant, displayName string, now time.Time, crlOrigins []string) (rootPEM, issuingPEM, issuingKeyPEM string, sealedRootCRL []byte, err error) {
	fail := func(e error) (string, string, string, []byte, error) { return "", "", "", nil, e }
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return fail(fmt.Errorf("an organization must be named"))
	}
	name := strings.TrimSpace(displayName)
	if name == "" {
		name = tenant
	}
	createdAt := now.UTC()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fail(fmt.Errorf("generate the organization's root key: %w", err))
	}
	rootSerial, err := mintSerial()
	if err != nil {
		return fail(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName:         name + " Interception Root",
			Organization:       []string{name},
			OrganizationalUnit: []string{tenant},
		},
		NotBefore:             createdAt.Add(-time.Minute),
		NotAfter:              createdAt.Add(tenantInterceptionRootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// ★ ROOM FOR TWO BELOW: the issuing CA this mints, and the short-lived per-Edge tier the control plane
		// mints under THAT. A root with less room produces a chain openssl calls "path length constraint
		// exceeded" and Chrome accepts — which is how one of these reached a device and was found by git
		// failing rather than by a browser.
		MaxPathLen: 2,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return fail(fmt.Errorf("create the organization's root: %w", err))
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return fail(fmt.Errorf("parse the organization's root: %w", err))
	}

	issuingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fail(fmt.Errorf("generate the issuing key: %w", err))
	}
	issuingSerial, err := mintSerial()
	if err != nil {
		return fail(err)
	}
	issuingTemplate := &x509.Certificate{
		SerialNumber: issuingSerial,
		Subject: pkix.Name{
			CommonName:         name + " Interception Issuing CA",
			Organization:       []string{name},
			OrganizationalUnit: []string{tenant},
		},
		NotBefore:             createdAt.Add(-time.Minute),
		NotAfter:              createdAt.Add(tenantInterceptionIssuingValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// ★★★ AT LEAST ONE, AND Import REFUSES ANYTHING LESS. The control plane mints a short-lived per-Edge
		// CA underneath this one so the long-lived key never reaches a node; pathLenConstraint:0 here would
		// make every chain that tier signs invalid. The import path says so in the customer's terms — this
		// mints material that passes its own check rather than a special case around it.
		MaxPathLen: 1,
	}
	if len(crlOrigins) > 0 {
		points, pointErr := inspectioncrl.URLs(crlOrigins, tenant, root)
		if pointErr != nil {
			return fail(fmt.Errorf("the deployment's revocation origins cannot name this organization's lists: %w", pointErr))
		}
		issuingTemplate.CRLDistributionPoints = points
	}
	issuingDER, err := x509.CreateCertificate(rand.Reader, issuingTemplate, root, &issuingKey.PublicKey, rootKey)
	if err != nil {
		return fail(fmt.Errorf("sign the issuing authority: %w", err))
	}
	issuingKeyDER, err := x509.MarshalECPrivateKey(issuingKey)
	if err != nil {
		return fail(fmt.Errorf("encode the issuing key: %w", err))
	}

	if len(crlOrigins) > 0 {
		issuing, parseErr := x509.ParseCertificate(issuingDER)
		if parseErr != nil {
			return fail(fmt.Errorf("parse the issuing authority: %w", parseErr))
		}
		// The last thing this root's key does.
		sealedRootCRL, err = inspectioncrl.SignSealed(root, rootKey, createdAt, issuing.NotAfter)
		if err != nil {
			return fail(fmt.Errorf("seal the root's revocation list: %w", err))
		}
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuingDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: issuingKeyDER})),
		sealedRootCRL, nil
}

func mintSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate a serial: %w", err)
	}
	return serial, nil
}
