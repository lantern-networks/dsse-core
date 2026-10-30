// Package inspectioncrl validates complete signed revocation information.
// The issuer key stays with its custodian; this package never invents "good"
// status for a missing, expired, or administratively revoked certificate.
package inspectioncrl

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"time"
)

const MaxDERBytes = 1 << 20
const MaxValidity = 7 * 24 * time.Hour

func Fingerprint(issuer *x509.Certificate) string {
	if issuer == nil {
		return ""
	}
	sum := sha256.Sum256(issuer.Raw)
	return hex.EncodeToString(sum[:])
}

func URL(base, tenant string, issuer *x509.Certificate) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("CRL base must be an HTTP origin; CRL signatures authenticate status without recursive TLS")
	}
	if tenant == "" || strings.TrimSpace(tenant) != tenant || strings.ContainsAny(tenant, "/\\\x00") || issuer == nil {
		return "", fmt.Errorf("invalid tenant or issuer")
	}
	u.Path = "/pki/crl/" + tenant + "/" + Fingerprint(issuer) + ".crl"
	return u.String(), nil
}

// URLs builds equivalent signed-CRL locations at independent HTTP origins.
// A certificate with only one node's address would make online revocation a
// single-node dependency even when the Edge and control plane can fail over.
func URLs(bases []string, tenant string, issuer *x509.Certificate) ([]string, error) {
	if len(bases) == 0 || len(bases) > 8 {
		return nil, fmt.Errorf("one to eight CRL origins required")
	}
	points := make([]string, 0, len(bases))
	seen := make(map[string]bool, len(bases))
	for _, base := range bases {
		if base == "" || strings.TrimSpace(base) != base {
			return nil, fmt.Errorf("invalid CRL origin")
		}
		point, err := URL(base, tenant, issuer)
		if err != nil {
			return nil, err
		}
		parsed, _ := url.Parse(point) // URL already verified its syntax and HTTP scheme.
		port := parsed.Port()
		if port == "" {
			port = "80"
		}
		originKey := strings.ToLower(parsed.Hostname()) + "\x00" + port
		if seen[originKey] {
			return nil, fmt.Errorf("duplicate CRL origin")
		}
		seen[originKey] = true
		points = append(points, point)
	}
	return points, nil
}

// BasesFromPoints verifies that every encoded distribution point binds the
// same tenant and signing issuer. The returned origins preserve preference
// order, so older single-origin material remains compatible.
func BasesFromPoints(points []string, tenant string, issuer *x509.Certificate) ([]string, error) {
	if len(points) == 0 || len(points) > 8 {
		return nil, fmt.Errorf("one to eight CRL distribution points required")
	}
	bases := make([]string, 0, len(points))
	for _, point := range points {
		u, err := url.Parse(point)
		if err != nil {
			return nil, err
		}
		base := u.Scheme + "://" + u.Host
		expected, err := URL(base, tenant, issuer)
		if err != nil || expected != point {
			return nil, fmt.Errorf("CRL URL must bind the tenant and issuer fingerprint")
		}
		bases = append(bases, base)
	}
	if _, err := URLs(bases, tenant, issuer); err != nil {
		return nil, err
	}
	return bases, nil
}

func ParseAndValidate(der []byte, issuer *x509.Certificate, now time.Time) (*x509.RevocationList, error) {
	if len(der) == 0 || len(der) > MaxDERBytes || issuer == nil {
		return nil, fmt.Errorf("missing or oversized CRL")
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, err
	}
	if err = list.CheckSignatureFrom(issuer); err != nil {
		return nil, fmt.Errorf("CRL issuer signature: %w", err)
	}
	if !bytes.Equal(list.RawIssuer, issuer.RawSubject) || !bytes.Equal(list.AuthorityKeyId, issuer.SubjectKeyId) {
		return nil, fmt.Errorf("CRL issuer identity mismatch")
	}
	if now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) || list.ThisUpdate.After(now.Add(time.Minute)) || !list.NextUpdate.After(now) || !list.NextUpdate.After(list.ThisUpdate) || list.NextUpdate.Sub(list.ThisUpdate) > MaxValidity || list.NextUpdate.After(issuer.NotAfter) {
		return nil, fmt.Errorf("CRL or issuer is stale, future, or exceeds its validity bound")
	}
	if list.Number == nil || list.Number.Sign() <= 0 {
		return nil, fmt.Errorf("CRL number must be positive")
	}
	seen := map[string]bool{}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 || entry.RevocationTime.After(now.Add(time.Minute)) || entry.ReasonCode < 0 || entry.ReasonCode > 10 || entry.ReasonCode == 7 || entry.ReasonCode == 8 || seen[entry.SerialNumber.String()] {
			return nil, fmt.Errorf("invalid, duplicate, or removal revocation entry")
		}
		seen[entry.SerialNumber.String()] = true
	}
	return list, nil
}

// AcceptUpdate rejects rollback, same-number equivocation and removal of known
// revocations. A stale prior CRL may be replaced, but its signed denials survive.
func AcceptUpdate(prior, next []byte, issuer *x509.Certificate, now time.Time) error {
	newer, err := ParseAndValidate(next, issuer, now)
	if err != nil {
		return err
	}
	if len(prior) == 0 {
		return nil
	}
	older, err := x509.ParseRevocationList(prior)
	if err != nil {
		return err
	}
	if err = older.CheckSignatureFrom(issuer); err != nil {
		return err
	}
	if bytes.Equal(prior, next) {
		return nil
	}
	if older.Number == nil || newer.Number.Cmp(older.Number) <= 0 || newer.ThisUpdate.Before(older.ThisUpdate) {
		return fmt.Errorf("CRL rollback or same-number equivocation")
	}
	denials := map[string]time.Time{}
	for _, e := range newer.RevokedCertificateEntries {
		denials[e.SerialNumber.String()] = e.RevocationTime
	}
	for _, e := range older.RevokedCertificateEntries {
		at, ok := denials[e.SerialNumber.String()]
		if !ok || !at.Equal(e.RevocationTime) {
			return fmt.Errorf("known revocation cannot be removed or postponed")
		}
	}
	return nil
}

func Sign(issuer *x509.Certificate, key crypto.Signer, number *big.Int, entries []x509.RevocationListEntry, now time.Time, validity time.Duration) ([]byte, error) {
	if issuer == nil || key == nil || number == nil || number.Sign() <= 0 || validity <= 0 || validity > MaxValidity {
		return nil, fmt.Errorf("invalid CRL signing parameters")
	}
	keyDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	issuerDER, err := x509.MarshalPKIXPublicKey(issuer.PublicKey)
	if err != nil || !bytes.Equal(keyDER, issuerDER) {
		return nil, fmt.Errorf("CRL signing key does not belong to issuer")
	}
	next := now.Add(validity)
	if next.After(issuer.NotAfter) {
		next = issuer.NotAfter
	}
	if !next.After(now) {
		return nil, fmt.Errorf("issuer has expired")
	}
	copied := append([]x509.RevocationListEntry(nil), entries...)
	for _, e := range copied {
		if e.SerialNumber == nil || e.SerialNumber.Sign() <= 0 {
			return nil, fmt.Errorf("positive revocation serial required")
		}
	}
	sort.Slice(copied, func(i, j int) bool { return copied[i].SerialNumber.Cmp(copied[j].SerialNumber) < 0 })
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: number, ThisUpdate: now.UTC(), NextUpdate: next.UTC(), RevokedCertificateEntries: copied}, issuer, key)
	if err != nil {
		return nil, err
	}
	_, err = ParseAndValidate(der, issuer, now)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// CheckChain requires status for every non-anchor element, including both CAs
// in root -> issuing -> Edge -> leaf. Missing status fails closed.
func CheckChain(chain []*x509.Certificate, lists map[string][]byte, now time.Time) error {
	if len(chain) < 2 {
		return fmt.Errorf("complete chain required")
	}
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for _, cert := range chain {
		if cert == nil {
			return fmt.Errorf("nil certificate")
		}
	}
	roots.AddCert(chain[len(chain)-1])
	for _, cert := range chain[1 : len(chain)-1] {
		intermediates.AddCert(cert)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return err
	}
	for i := 0; i < len(chain)-1; i++ {
		cert, issuer := chain[i], chain[i+1]
		if err := cert.CheckSignatureFrom(issuer); err != nil {
			return err
		}
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return fmt.Errorf("certificate expired or not yet valid")
		}
		list, err := ParseAndValidate(lists[Fingerprint(issuer)], issuer, now)
		if err != nil {
			return err
		}
		for _, entry := range list.RevokedCertificateEntries {
			if cert.SerialNumber.Cmp(entry.SerialNumber) == 0 {
				return fmt.Errorf("certificate revoked")
			}
		}
	}
	return nil
}
