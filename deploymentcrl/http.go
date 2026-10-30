package deploymentcrl

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

// Handler exposes only verified DER. The publication process holds public CA
// certificates and CRLs, never an authority key or revocation ledger.
func Handler(publicDir string, root *x509.Certificate, issuers []*x509.Certificate, origins []string) (http.Handler, error) {
	if publicDir == "" || root == nil || len(issuers) == 0 {
		return nil, fmt.Errorf("deployment CRL publication requires a root, issuers, and public directory")
	}
	if info, err := os.Lstat(publicDir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("deployment CRL publication directory must be a real directory")
	}
	allowedHosts := map[string]bool{}
	for _, origin := range origins {
		if _, err := DistributionPoints([]string{origin}, root, root); err != nil {
			return nil, err
		}
		u, _ := url.Parse(origin)
		allowedHosts[strings.ToLower(u.Host)] = true
	}
	if len(allowedHosts) == 0 {
		return nil, fmt.Errorf("no deployment CRL HTTP host configured")
	}
	routes := map[string]*x509.Certificate{}
	for _, issuer := range issuers {
		if issuer == nil || issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
			return nil, fmt.Errorf("invalid deployment CRL issuer")
		}
		id := Fingerprint(issuer)
		if _, exists := routes[id]; exists {
			return nil, fmt.Errorf("duplicate deployment CRL issuer")
		}
		routes[id] = issuer
	}
	rootID := Fingerprint(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Lstat(filepath.Join(publicDir, publicationMarker)); err == nil || !os.IsNotExist(err) {
			http.Error(w, "revocation status unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !allowedHosts[strings.ToLower(r.Host)] || r.URL.RawQuery != "" || r.URL.Fragment != "" || r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		prefix := "/pki/deployment-crl/" + rootID + "/"
		if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, ".crl") {
			http.NotFound(w, r)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), ".crl")
		issuer := routes[id]
		if issuer == nil || id != Fingerprint(issuer) {
			http.NotFound(w, r)
			return
		}
		path := filepath.Join(publicDir, id+".crl")
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			http.Error(w, "revocation status unavailable", http.StatusServiceUnavailable)
			return
		}
		der, err := os.ReadFile(path)
		if err != nil || len(der) > inspectioncrl.MaxDERBytes {
			http.Error(w, "revocation status unavailable", http.StatusServiceUnavailable)
			return
		}
		if _, err := inspectioncrl.ParseAndValidate(der, issuer, time.Now().UTC()); err != nil {
			http.Error(w, "revocation status unavailable", http.StatusServiceUnavailable)
			return
		}
		if _, err := os.Lstat(filepath.Join(publicDir, publicationMarker)); err == nil || !os.IsNotExist(err) {
			http.Error(w, "revocation status unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(der)
		}
	}), nil
}
