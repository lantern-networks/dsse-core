package deploymentcrl

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

const (
	ledgerFile        = "deployment-crl-ledger.json"
	publicationMarker = ".deployment-crl-publishing"
)

// Issuer is kept only on the signing host. No serving process needs its Key.
type Issuer struct {
	Certificate *x509.Certificate
	Key         crypto.Signer
}

type Revocation struct {
	Issuer      *x509.Certificate
	Certificate *x509.Certificate
	Reason      int
}

type revokedSerial struct {
	Serial string    `json:"serial"`
	At     time.Time `json:"at"`
	Reason int       `json:"reason"`
}

type issuerLedger struct {
	Number      uint64          `json:"number"`
	Revocations []revokedSerial `json:"revocations,omitempty"`
}

type ledger struct {
	Version        int                     `json:"version"`
	DeploymentRoot string                  `json:"deployment_root"`
	Issuers        map[string]issuerLedger `json:"issuers"`
}

func readLedger(path, rootFingerprint string) (ledger, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ledger{Version: 1, DeploymentRoot: rootFingerprint, Issuers: map[string]issuerLedger{}}, nil
	}
	if err != nil {
		return ledger{}, err
	}
	if len(b) == 0 || len(b) > 4<<20 {
		return ledger{}, fmt.Errorf("invalid deployment CRL ledger size")
	}
	var l ledger
	if err := json.Unmarshal(b, &l); err != nil {
		return ledger{}, err
	}
	if l.Version != 1 || l.DeploymentRoot != rootFingerprint || l.Issuers == nil {
		return ledger{}, fmt.Errorf("deployment CRL ledger does not belong to this authority")
	}
	for id, state := range l.Issuers {
		if len(id) != 64 || state.Number == 0 {
			return ledger{}, fmt.Errorf("invalid issuer state in deployment CRL ledger")
		}
		seen := map[string]bool{}
		for _, entry := range state.Revocations {
			serial, ok := new(big.Int).SetString(entry.Serial, 10)
			if !ok || serial.Sign() <= 0 || entry.At.IsZero() || entry.Reason < 0 || entry.Reason > 10 || entry.Reason == 7 || entry.Reason == 8 || seen[entry.Serial] {
				return ledger{}, fmt.Errorf("invalid revocation in deployment CRL ledger")
			}
			seen[entry.Serial] = true
		}
	}
	return l, nil
}

func validateIssuer(root *x509.Certificate, issuer Issuer) error {
	if root == nil || issuer.Certificate == nil || issuer.Key == nil || issuer.Certificate.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return fmt.Errorf("CRL signer must be an issuing CA with a private key")
	}
	if Fingerprint(root) != Fingerprint(issuer.Certificate) {
		if err := issuer.Certificate.CheckSignatureFrom(root); err != nil {
			return fmt.Errorf("issuer is not signed by this deployment root: %w", err)
		}
	}
	return nil
}

// Refresh signs every deployment issuer's complete revocation set. The durable
// ledger is advanced before publication; an interrupted publication is exposed
// by Ready rather than silently claiming that an unpublished revocation took
// effect. A subsequent refresh always uses a greater CRL number.
func Refresh(authorityDir, publicDir string, root *x509.Certificate, issuers []Issuer, additions []Revocation, now time.Time) error {
	if root == nil || len(issuers) == 0 || authorityDir == "" || publicDir == "" {
		return fmt.Errorf("deployment root, issuer keys, and both directories required")
	}
	if err := os.MkdirAll(authorityDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(publicDir, 0o755); err != nil {
		return err
	}
	for _, path := range []string{authorityDir, publicDir} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("deployment CRL directory must be a real directory: %s", path)
		}
	}
	lock, err := os.OpenFile(filepath.Join(authorityDir, ".deployment-crl.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lockIssuerLedger(lock); err != nil {
		return err
	}
	defer unlockIssuerLedger(lock)
	rootID := Fingerprint(root)
	statePath := filepath.Join(authorityDir, ledgerFile)
	state, err := readLedger(statePath, rootID)
	if err != nil {
		return err
	}
	byID := map[string]Issuer{}
	for _, spec := range issuers {
		if err := validateIssuer(root, spec); err != nil {
			return err
		}
		id := Fingerprint(spec.Certificate)
		if _, exists := byID[id]; exists {
			return fmt.Errorf("duplicate deployment CRL issuer")
		}
		byID[id] = spec
	}
	for _, added := range additions {
		if added.Issuer == nil || added.Certificate == nil || added.Certificate.SerialNumber == nil || added.Certificate.SerialNumber.Sign() <= 0 || added.Reason < 0 || added.Reason > 10 || added.Reason == 7 || added.Reason == 8 {
			return fmt.Errorf("invalid certificate revocation request")
		}
		id := Fingerprint(added.Issuer)
		if _, ok := byID[id]; !ok {
			return fmt.Errorf("revocation issuer is not held by this deployment")
		}
		if err := added.Certificate.CheckSignatureFrom(added.Issuer); err != nil {
			return fmt.Errorf("revocation certificate was not signed by the selected issuer: %w", err)
		}
		item := state.Issuers[id]
		for _, existing := range item.Revocations {
			if existing.Serial == added.Certificate.SerialNumber.String() {
				return fmt.Errorf("certificate already revoked")
			}
		}
		item.Revocations = append(item.Revocations, revokedSerial{Serial: added.Certificate.SerialNumber.String(), At: now.UTC().Truncate(time.Second), Reason: added.Reason})
		state.Issuers[id] = item
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	type publication struct {
		path string
		der  []byte
	}
	toPublish := make([]publication, 0, len(ids))
	for _, id := range ids {
		spec := byID[id]
		item := state.Issuers[id]
		if item.Number == ^uint64(0) {
			return fmt.Errorf("deployment CRL number exhausted")
		}
		item.Number++
		entries := make([]x509.RevocationListEntry, 0, len(item.Revocations))
		for _, revoked := range item.Revocations {
			serial, _ := new(big.Int).SetString(revoked.Serial, 10)
			entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: revoked.At, ReasonCode: revoked.Reason})
		}
		der, err := inspectioncrl.Sign(spec.Certificate, spec.Key, new(big.Int).SetUint64(item.Number), entries, now.UTC(), DefaultValidity)
		if err != nil {
			return err
		}
		path := filepath.Join(publicDir, id+".crl")
		old, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := inspectioncrl.AcceptUpdate(old, der, spec.Certificate, now.UTC()); err != nil {
			return fmt.Errorf("refuse deployment CRL rollback: %w", err)
		}
		state.Issuers[id] = item
		toPublish = append(toPublish, publication{path, der})
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	// A keyless publisher must not serve a previously signed CRL while the
	// issuer ledger has advanced but publication has not completed. Leave this
	// marker behind on every interrupted update; the next successful refresh
	// can repair the publication and remove it.
	markerPath := filepath.Join(publicDir, publicationMarker)
	if err := atomicWrite(markerPath, []byte("updating\n"), 0o644); err != nil {
		return err
	}
	if err := atomicWrite(statePath, append(encoded, '\n'), 0o600); err != nil {
		return err
	}
	for _, next := range toPublish {
		if err := atomicWrite(next.path, next.der, 0o644); err != nil {
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

func atomicWrite(path string, contents []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".deployment-crl-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(contents); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Ready is the issuer-side gate. A missing or lagging published CRL, including
// after a failed refresh, keeps service setup from claiming Online readiness.
func Ready(authorityDir, publicDir string, root *x509.Certificate, issuers []*x509.Certificate, now time.Time, minimumRemaining time.Duration) error {
	if root == nil || minimumRemaining < 0 {
		return fmt.Errorf("invalid deployment CRL readiness arguments")
	}
	if _, err := os.Lstat(filepath.Join(publicDir, publicationMarker)); err == nil {
		return fmt.Errorf("deployment CRL publication is incomplete")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	l, err := readLedger(filepath.Join(authorityDir, ledgerFile), Fingerprint(root))
	if err != nil {
		return err
	}
	if len(l.Issuers) == 0 {
		return fmt.Errorf("deployment CRLs have not been issued")
	}
	for _, issuer := range issuers {
		if issuer == nil {
			return fmt.Errorf("nil deployment issuer")
		}
		id := Fingerprint(issuer)
		expected, ok := l.Issuers[id]
		if !ok {
			return fmt.Errorf("deployment issuer has no CRL ledger")
		}
		der, err := os.ReadFile(filepath.Join(publicDir, id+".crl"))
		if err != nil {
			return err
		}
		actual, err := inspectioncrl.ParseAndValidate(der, issuer, now)
		if err != nil {
			return err
		}
		if !actual.NextUpdate.After(now.Add(minimumRemaining)) || actual.Number.Cmp(new(big.Int).SetUint64(expected.Number)) != 0 {
			return fmt.Errorf("published deployment CRL is stale or behind its ledger")
		}
		if len(actual.RevokedCertificateEntries) != len(expected.Revocations) {
			return fmt.Errorf("published deployment CRL omits revocations")
		}
		for _, entry := range expected.Revocations {
			found := false
			for _, got := range actual.RevokedCertificateEntries {
				if got.SerialNumber.String() == entry.Serial && got.RevocationTime.Equal(entry.At) && got.ReasonCode == entry.Reason {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("published deployment CRL omits a revocation")
			}
		}
	}
	return nil
}
