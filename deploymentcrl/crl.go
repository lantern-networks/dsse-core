// Package deploymentcrl manages revocation status for certificates issued by
// the deployment PKI. It is deliberately separate from tenant inspection CRLs:
// a tenant's interception authority must never sign deployment status.
package deploymentcrl

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

const DefaultValidity = 24 * time.Hour

func Fingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// DistributionPoints returns public, credential-free HTTP locations. The
// deployment and issuer fingerprints bind a URL to exactly one signing key.
// Independent origins may publish the same signed DER for failover.
func DistributionPoints(origins []string, root, issuer *x509.Certificate) ([]string, error) {
	if root == nil || issuer == nil || len(origins) == 0 || len(origins) > 8 {
		return nil, fmt.Errorf("one to eight deployment CRL origins and both certificates required")
	}
	result := make([]string, 0, len(origins))
	seen := map[string]bool{}
	for _, raw := range origins {
		if raw == "" || strings.TrimSpace(raw) != raw {
			return nil, fmt.Errorf("invalid deployment CRL origin")
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
			return nil, fmt.Errorf("deployment CRL origin must be a plain HTTP origin")
		}
		if strings.ContainsAny(u.Host, "\\\x00\r\n") {
			return nil, fmt.Errorf("invalid deployment CRL host")
		}
		port := u.Port()
		if port == "" {
			port = "80"
		}
		identity := strings.ToLower(u.Hostname()) + "\x00" + port
		if seen[identity] {
			return nil, fmt.Errorf("duplicate deployment CRL origin")
		}
		seen[identity] = true
		u.Path = "/pki/deployment-crl/" + Fingerprint(root) + "/" + Fingerprint(issuer) + ".crl"
		result = append(result, u.String())
	}
	return result, nil
}

// VerifyStatus requires a fresh, issuer-signed CRL and a certificate chain.
// The root anchor itself is not checked for revocation; every non-root member is.
func VerifyStatus(chain []*x509.Certificate, lists map[string][]byte, now time.Time) error {
	if len(chain) < 2 {
		return fmt.Errorf("complete deployment chain required")
	}
	for i := 0; i < len(chain)-1; i++ {
		if chain[i] == nil || chain[i+1] == nil {
			return fmt.Errorf("nil deployment certificate")
		}
		issuer := chain[i+1]
		if len(chain[i].CRLDistributionPoints) == 0 {
			return fmt.Errorf("deployment certificate has no CRL distribution point")
		}
		if _, err := DistributionPointsFromCertificate(chain[i], chain[len(chain)-1], issuer); err != nil {
			return err
		}
	}
	return inspectioncrl.CheckChain(chain, lists, now)
}

// DistributionPointsFromCertificate rejects a CDP that points to a different
// deployment, a different issuer, HTTPS-only recursive trust, or a URL carrying
// credentials or query parameters.
func DistributionPointsFromCertificate(cert, root, issuer *x509.Certificate) ([]string, error) {
	if cert == nil || root == nil || issuer == nil || len(cert.CRLDistributionPoints) == 0 {
		return nil, fmt.Errorf("deployment CRL distribution point missing")
	}
	origins := make([]string, 0, len(cert.CRLDistributionPoints))
	for _, point := range cert.CRLDistributionPoints {
		u, err := url.Parse(point)
		if err != nil {
			return nil, err
		}
		origin := u.Scheme + "://" + u.Host
		expected, err := DistributionPoints([]string{origin}, root, issuer)
		if err != nil || len(expected) != 1 || expected[0] != point {
			return nil, fmt.Errorf("deployment CDP does not bind this root and issuer")
		}
		origins = append(origins, origin)
	}
	if _, err := DistributionPoints(origins, root, issuer); err != nil {
		return nil, err
	}
	return origins, nil
}
