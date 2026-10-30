package deploymentcrl

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

// Replicate copies only issuer-signed DER to a second publication host. The
// deployment root and issuing CA certificates are pinned local inputs; no key
// or revocation ledger is needed on the replica. All issuers are fetched and
// checked before publication is made unavailable for the short update.
func Replicate(ctx context.Context, sourceOrigin, publicDir string, root *x509.Certificate, issuers []*x509.Certificate, client *http.Client, now time.Time, minimumRemaining time.Duration) error {
	if err := validateReplicaAuthorities(root, issuers, now); err != nil {
		return err
	}
	if minimumRemaining < 0 || minimumRemaining >= inspectioncrl.MaxValidity {
		return fmt.Errorf("invalid replica minimum CRL lifetime")
	}
	rootPoints, err := DistributionPoints([]string{sourceOrigin}, root, root)
	if err != nil {
		return err
	}
	for _, issuer := range issuers {
		if Fingerprint(issuer) != Fingerprint(root) && !slices.Contains(issuer.CRLDistributionPoints, rootPoints[0]) {
			return fmt.Errorf("source origin is not encoded in an issuing CA's signed CDP")
		}
	}
	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		return err
	}
	if err := realDirectory(publicDir); err != nil {
		return err
	}
	// A second updater must not compare against a moving prior version.
	lock, err := os.OpenFile(filepath.Join(publicDir, ".deployment-crl-replica.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lockIssuerLedger(lock); err != nil {
		return err
	}
	defer unlockIssuerLedger(lock)
	if client == nil {
		client = &http.Client{}
	}
	probeClient := *client
	probeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	type publication struct {
		path string
		der  []byte
	}
	next := make([]publication, 0, len(issuers))
	for _, issuer := range issuers {
		points, err := DistributionPoints([]string{sourceOrigin}, root, issuer)
		if err != nil {
			return err
		}
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, points[0], nil)
		if err != nil {
			cancel()
			return err
		}
		resp, err := probeClient.Do(req)
		if err != nil {
			cancel()
			return fmt.Errorf("source deployment CRL unavailable: %w", err)
		}
		der, readErr := io.ReadAll(io.LimitReader(resp.Body, inspectioncrl.MaxDERBytes+1))
		closeErr := resp.Body.Close()
		cancel()
		if readErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK || len(der) > inspectioncrl.MaxDERBytes {
			return fmt.Errorf("source deployment CRL did not return bounded signed status")
		}
		list, err := inspectioncrl.ParseAndValidate(der, issuer, now)
		if err != nil || !list.NextUpdate.After(now.Add(minimumRemaining)) {
			return fmt.Errorf("source deployment CRL has invalid signature, issuer, or freshness")
		}
		path := filepath.Join(publicDir, Fingerprint(issuer)+".crl")
		prior, err := readReplicaPrior(path)
		if err != nil {
			return err
		}
		if err := inspectioncrl.AcceptUpdate(prior, der, issuer, now); err != nil {
			return fmt.Errorf("source deployment CRL rolls back a published status: %w", err)
		}
		next = append(next, publication{path: path, der: der})
	}
	markerPath := filepath.Join(publicDir, publicationMarker)
	if err := atomicWrite(markerPath, []byte("updating\n"), 0o644); err != nil {
		return err
	}
	// An interrupted update deliberately leaves the marker in place. The
	// keyless HTTP handler then returns 503 rather than a mixed issuer set.
	for _, item := range next {
		if err := atomicWrite(item.path, item.der, 0o644); err != nil {
			return err
		}
	}
	if err := os.Remove(markerPath); err != nil {
		return err
	}
	d, err := os.Open(publicDir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ReplicaReady checks a keyless publication without the issuer's private
// ledger. It is also usable while the signer host is down: only locally pinned
// CA certificates and the current signed CRLs are needed.
func ReplicaReady(publicDir string, root *x509.Certificate, issuers []*x509.Certificate, now time.Time, minimumRemaining time.Duration) error {
	if err := validateReplicaAuthorities(root, issuers, now); err != nil {
		return err
	}
	if minimumRemaining < 0 || minimumRemaining >= inspectioncrl.MaxValidity {
		return fmt.Errorf("invalid replica minimum CRL lifetime")
	}
	if err := realDirectory(publicDir); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(publicDir, publicationMarker)); err == nil {
		return fmt.Errorf("deployment CRL replica publication is incomplete")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, issuer := range issuers {
		der, err := readReplicaPrior(filepath.Join(publicDir, Fingerprint(issuer)+".crl"))
		if err != nil || len(der) == 0 {
			return fmt.Errorf("deployment CRL replica status is missing or unreadable")
		}
		list, err := inspectioncrl.ParseAndValidate(der, issuer, now)
		if err != nil || !list.NextUpdate.After(now.Add(minimumRemaining)) {
			return fmt.Errorf("deployment CRL replica status is invalid or too close to expiry")
		}
	}
	return nil
}

func validateReplicaAuthorities(root *x509.Certificate, issuers []*x509.Certificate, now time.Time) error {
	if root == nil || len(issuers) == 0 || root.KeyUsage&x509.KeyUsageCRLSign == 0 || !root.IsCA {
		return fmt.Errorf("deployment CRL replica requires a root and issuing CAs")
	}
	if err := root.CheckSignatureFrom(root); err != nil || now.Before(root.NotBefore) || !now.Before(root.NotAfter) {
		return fmt.Errorf("deployment CRL replica root is not a current self-signed CA")
	}
	seen := map[string]bool{}
	rootPresent := false
	for _, issuer := range issuers {
		if issuer == nil || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCRLSign == 0 || now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) {
			return fmt.Errorf("invalid deployment CRL replica issuer")
		}
		id := Fingerprint(issuer)
		if seen[id] {
			return fmt.Errorf("duplicate deployment CRL replica issuer")
		}
		seen[id] = true
		if bytes.Equal(issuer.Raw, root.Raw) {
			rootPresent = true
		} else if err := issuer.CheckSignatureFrom(root); err != nil {
			return fmt.Errorf("deployment CRL replica issuer is not signed by pinned root: %w", err)
		}
	}
	if !rootPresent {
		return fmt.Errorf("deployment CRL replica root status is missing")
	}
	return nil
}

func realDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("deployment CRL replica requires a real publication directory")
	}
	return nil
}

func readReplicaPrior(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > inspectioncrl.MaxDERBytes {
		return nil, fmt.Errorf("invalid deployment CRL replica status file")
	}
	return os.ReadFile(path)
}
