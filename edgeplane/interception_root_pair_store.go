package edgeplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/durablefile"
)

// The snapshot is the only authoritative file. The historical certificate and
// key filenames remain compatible views, rebuilt after an interrupted write.
// Readers of the pair must use LoadNetworkExtensionLabTLSPersistentRootMaterial,
// which holds the same lock as writers while checking and repairing those views.
type persistedInterceptionRootPair struct {
	Version  int    `json:"version"`
	PathHash string `json:"path_hash"`
	CertPEM  []byte `json:"cert_pem"`
	KeyDisk  []byte `json:"key_disk"`
}

type interceptionRootPairIO struct {
	write   func(string, []byte, os.FileMode) error
	syncDir func(string) error
}

var productionInterceptionRootPairIO = interceptionRootPairIO{write: durablefile.Write, syncDir: durablefile.SyncDir}

var interceptionRootLocalLocks sync.Map // canonical directory -> *sync.Mutex

func interceptionRootSnapshotPath(certPath string) string { return certPath + ".pair.json" }

// NetworkExtensionLabTLSActiveAnchorExportPath is a public-certificate-only
// output, separate from the historical signing material pair. The output is
// derived from the resolved certificate path, so legacy directory names keep
// their own export rather than accidentally switching to a new root.
func NetworkExtensionLabTLSActiveAnchorExportPath(certPath string) string {
	if strings.TrimSpace(certPath) == "" {
		return ""
	}
	ext := filepath.Ext(certPath)
	return strings.TrimSuffix(certPath, ext) + ".active-anchor.pem"
}

func writeInterceptionActiveAnchor(path string, pemBytes []byte, io interceptionRootPairIO) error {
	if path == "" || len(pemBytes) == 0 {
		return fmt.Errorf("active interception anchor path and certificate are required")
	}
	if _, err := ParseInterceptionCertPEM(pemBytes); err != nil {
		return err
	}
	err := io.write(path, pemBytes, 0600)
	if errors.Is(err, durablefile.ErrReplacedNotFlushed) {
		got, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(got, pemBytes) {
			return fmt.Errorf("active interception anchor replacement is uncertain: %w", err)
		}
		if syncErr := io.syncDir(filepath.Dir(path)); syncErr != nil {
			return fmt.Errorf("active interception anchor directory is not durable: %w", errors.Join(err, syncErr))
		}
		return nil
	}
	return err
}

func interceptionRootPathHash(certPath string) (string, error) {
	abs, err := filepath.Abs(certPath)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(filepath.Clean(abs)))
	return hex.EncodeToString(sum[:]), nil
}

func canonicalInterceptionRootOutputPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

func withInterceptionRootPairLock(input string, fn func(string) error) error {
	input = strings.TrimSpace(input)
	if input == "" {
		return fn("")
	}
	abs, err := filepath.Abs(input)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	if info, statErr := os.Stat(abs); statErr == nil && info.IsDir() {
		dir = abs
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("stat interception root path: %w", statErr)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create interception root directory: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	} else {
		return fmt.Errorf("resolve interception root directory: %w", err)
	}
	value, _ := interceptionRootLocalLocks.LoadOrStore(dir, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	// LockDevice uses flock / LockFileEx and releases on process death. Keep the
	// lock inode forever; removing it permits two writers to own different locks.
	lock, err := agentupdate.LockDevice(filepath.Join(dir, ".dsse-interception-root.lock"))
	if err != nil {
		return fmt.Errorf("interception root pair is owned by another process: %w", err)
	}
	defer lock.Release()
	path, err := normalizeNetworkExtensionLabTLSRootCACertOutPath(input)
	if err != nil {
		return err
	}
	return fn(path)
}

func readInterceptionRootPairLocked(certPath string, now func() time.Time, io interceptionRootPairIO) (networkExtensionLabTLSRootMaterial, bool, error) {
	if certPath == "" {
		return networkExtensionLabTLSRootMaterial{}, false, nil
	}
	snapshotPath := interceptionRootSnapshotPath(certPath)
	data, err := os.ReadFile(snapshotPath)
	if err == nil {
		if err := validateNetworkExtensionLabTLSSecretFileMode(snapshotPath); err != nil {
			return networkExtensionLabTLSRootMaterial{}, false, err
		}
		var pair persistedInterceptionRootPair
		if err := json.Unmarshal(data, &pair); err != nil || pair.Version != 1 || len(pair.CertPEM) == 0 || len(pair.KeyDisk) == 0 {
			return networkExtensionLabTLSRootMaterial{}, false, fmt.Errorf("interception root snapshot is malformed")
		}
		wantPathHash, err := interceptionRootPathHash(certPath)
		if err != nil || pair.PathHash != wantPathHash {
			return networkExtensionLabTLSRootMaterial{}, false, fmt.Errorf("interception root snapshot is bound to another path")
		}
		keyPEM, err := maybeUnsealInterceptionKeyFromDisk(pair.KeyDisk)
		if err != nil {
			return networkExtensionLabTLSRootMaterial{}, false, err
		}
		material, err := parseNetworkExtensionLabTLSPersistentRootMaterial(pair.CertPEM, keyPEM)
		if err != nil {
			return networkExtensionLabTLSRootMaterial{}, false, err
		}
		if err := validatePersistentRootTime(material, now); err != nil {
			return networkExtensionLabTLSRootMaterial{}, false, err
		}
		if err := repairInterceptionRootViewsLocked(certPath, pair, io); err != nil {
			return networkExtensionLabTLSRootMaterial{}, false, err
		}
		return material, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return networkExtensionLabTLSRootMaterial{}, false, fmt.Errorf("read interception root snapshot: %w", err)
	}
	// A valid old two-file pair is migrated without changing its identity. A
	// surviving half is evidence of an interrupted old write, never a fresh root.
	material, diskKey, present, err := readLegacyInterceptionRootPair(certPath)
	if err != nil || !present {
		return material, present, err
	}
	if err := validatePersistentRootTime(material, now); err != nil {
		return networkExtensionLabTLSRootMaterial{}, false, err
	}
	pair, err := newPersistedInterceptionRootPair(certPath, material.CertPEM, diskKey)
	if err != nil {
		return networkExtensionLabTLSRootMaterial{}, false, err
	}
	if err := writeInterceptionRootSnapshotLocked(snapshotPath, pair, io); err != nil {
		return networkExtensionLabTLSRootMaterial{}, false, err
	}
	return material, true, nil
}

func readLegacyInterceptionRootPair(certPath string) (networkExtensionLabTLSRootMaterial, []byte, bool, error) {
	keyPath := NetworkExtensionLabTLSRootKeyPath(certPath)
	certPEM, certErr := os.ReadFile(certPath)
	keyDisk, keyErr := os.ReadFile(keyPath)
	certMissing, keyMissing := errors.Is(certErr, os.ErrNotExist), errors.Is(keyErr, os.ErrNotExist)
	if certMissing && keyMissing {
		return networkExtensionLabTLSRootMaterial{}, nil, false, nil
	}
	if certErr != nil && !certMissing {
		return networkExtensionLabTLSRootMaterial{}, nil, false, fmt.Errorf("read lab TLS persistent root certificate: %w", certErr)
	}
	if keyErr != nil && !keyMissing {
		return networkExtensionLabTLSRootMaterial{}, nil, false, fmt.Errorf("read lab TLS persistent root key: %w", keyErr)
	}
	if certMissing || keyMissing {
		return networkExtensionLabTLSRootMaterial{}, nil, false, fmt.Errorf("lab TLS persistent root certificate/key pair is incomplete; refusing to replace the existing trust anchor")
	}
	if err := validateNetworkExtensionLabTLSSecretFileMode(keyPath); err != nil {
		return networkExtensionLabTLSRootMaterial{}, nil, false, err
	}
	keyPEM, err := maybeUnsealInterceptionKeyFromDisk(keyDisk)
	if err != nil {
		return networkExtensionLabTLSRootMaterial{}, nil, false, err
	}
	material, err := parseNetworkExtensionLabTLSPersistentRootMaterial(certPEM, keyPEM)
	return material, keyDisk, true, err
}

func newPersistedInterceptionRootPair(certPath string, certPEM, keyDisk []byte) (persistedInterceptionRootPair, error) {
	hash, err := interceptionRootPathHash(certPath)
	if err != nil {
		return persistedInterceptionRootPair{}, err
	}
	return persistedInterceptionRootPair{Version: 1, PathHash: hash, CertPEM: bytes.Clone(certPEM), KeyDisk: bytes.Clone(keyDisk)}, nil
}

func writeInterceptionRootSnapshotLocked(path string, pair persistedInterceptionRootPair, io interceptionRootPairIO) error {
	data, err := json.Marshal(pair)
	if err != nil {
		return err
	}
	err = io.write(path, data, 0600)
	if errors.Is(err, durablefile.ErrReplacedNotFlushed) {
		got, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(got, data) {
			return fmt.Errorf("interception root snapshot replacement is uncertain: %w", err)
		}
		if syncErr := io.syncDir(filepath.Dir(path)); syncErr != nil {
			return fmt.Errorf("interception root snapshot directory is not durable: %w", errors.Join(err, syncErr))
		}
		return nil
	}
	return err
}

func repairInterceptionRootViewsLocked(certPath string, pair persistedInterceptionRootPair, io interceptionRootPairIO) error {
	for _, view := range []struct {
		path   string
		data   []byte
		secret bool
	}{
		{NetworkExtensionLabTLSRootKeyPath(certPath), pair.KeyDisk, true},
		{certPath, pair.CertPEM, false},
	} {
		got, err := os.ReadFile(view.path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read interception root compatibility view: %w", err)
		}
		if err == nil {
			// A key that was already exposed through broad permissions is an
			// operator-visible security failure, not an interrupted write to
			// silently repair from the authoritative snapshot.
			if view.secret {
				if modeErr := validateNetworkExtensionLabTLSSecretFileMode(view.path); modeErr != nil {
					return modeErr
				}
			}
			if bytes.Equal(got, view.data) && validateNetworkExtensionLabTLSSecretFileMode(view.path) == nil {
				continue
			}
		}
		if err := io.write(view.path, view.data, 0600); err != nil {
			if !errors.Is(err, durablefile.ErrReplacedNotFlushed) {
				return fmt.Errorf("restore interception root compatibility view: %w", err)
			}
			actual, readErr := os.ReadFile(view.path)
			if readErr != nil || !bytes.Equal(actual, view.data) || io.syncDir(filepath.Dir(view.path)) != nil {
				return fmt.Errorf("interception root compatibility view durability uncertain: %w", err)
			}
		}
	}
	return nil
}

func writeInterceptionRootPairLocked(certPath string, material networkExtensionLabTLSRootMaterial, io interceptionRootPairIO) error {
	if material.Cert == nil || material.Key == nil || len(material.CertPEM) == 0 || len(material.KeyPEM) == 0 {
		return fmt.Errorf("lab TLS persistent root material is incomplete")
	}
	if _, err := parseNetworkExtensionLabTLSPersistentRootMaterial(material.CertPEM, material.KeyPEM); err != nil {
		return err
	}
	current, _, err := readInterceptionRootPairLocked(certPath, nil, io)
	if err != nil {
		return err
	}
	if current.Cert != nil && (!bytes.Equal(current.Cert.Raw, material.Cert.Raw) || current.Key.PublicKey.N.Cmp(material.Key.PublicKey.N) != 0) {
		return fmt.Errorf("interception root replacement requires an explicit trust handoff")
	}
	keyDisk, err := maybeSealInterceptionKeyForDisk(material.KeyPEM)
	if err != nil {
		return fmt.Errorf("seal lab TLS root key: %w", err)
	}
	pair, err := newPersistedInterceptionRootPair(certPath, material.CertPEM, keyDisk)
	if err != nil {
		return err
	}
	if err := writeInterceptionRootSnapshotLocked(interceptionRootSnapshotPath(certPath), pair, io); err != nil {
		return err
	}
	return repairInterceptionRootViewsLocked(certPath, pair, io)
}

func interceptionRootNeedsKeySealMigrationLocked(certPath string) (bool, error) {
	data, err := os.ReadFile(interceptionRootSnapshotPath(certPath))
	if err != nil {
		return false, err
	}
	var pair persistedInterceptionRootPair
	if err := json.Unmarshal(data, &pair); err != nil || pair.Version != 1 {
		return false, fmt.Errorf("interception root snapshot is malformed")
	}
	return !isSealedInterceptionKeyPEM(pair.KeyDisk), nil
}

func loadOrCreateInterceptionRootPair(input string, now func() time.Time, scope string) (networkExtensionLabTLSRootMaterial, bool, error) {
	var material networkExtensionLabTLSRootMaterial
	var reused bool
	err := withInterceptionRootPairLock(input, func(certPath string) error {
		var err error
		material, reused, err = readInterceptionRootPairLocked(certPath, now, productionInterceptionRootPairIO)
		if err != nil {
			return err
		}
		if material.Cert == nil {
			material, err = GenerateNetworkExtensionLabTLSRootMaterialScoped(scope, now)
			if err != nil {
				return err
			}
			if certPath != "" {
				if err := writeInterceptionRootPairLocked(certPath, material, productionInterceptionRootPairIO); err != nil {
					return err
				}
			}
		} else if len(GetInterceptionRootKEK()) > 0 && certPath != "" {
			needsSeal, err := interceptionRootNeedsKeySealMigrationLocked(certPath)
			if err != nil {
				return err
			}
			if needsSeal {
				if err := writeInterceptionRootPairLocked(certPath, material, productionInterceptionRootPairIO); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return material, reused, err
}
