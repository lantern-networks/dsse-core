package edgeplane

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/durablefile"
)

func TestRootPairInterruptedCompatibilityViewsRecoverFromOneSnapshot(t *testing.T) {
	for _, failedView := range []string{"key", "certificate"} {
		t.Run(failedView, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "root.pem")
			material, err := GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
			if err != nil {
				t.Fatal(err)
			}
			failPath := path
			if failedView == "key" {
				failPath = NetworkExtensionLabTLSRootKeyPath(path)
			}
			io := interceptionRootPairIO{
				write: func(name string, data []byte, mode os.FileMode) error {
					if name == failPath {
						return errors.New("injected compatibility view failure")
					}
					return durablefile.Write(name, data, mode)
				},
				syncDir: durablefile.SyncDir,
			}
			if err := writeInterceptionRootPairLocked(path, material, io); err == nil {
				t.Fatal("interrupted view write was reported as a complete root")
			}
			if _, err := os.Stat(interceptionRootSnapshotPath(path)); err != nil {
				t.Fatalf("authoritative pair was not durably published first: %v", err)
			}
			loaded, reused, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(path, time.Now)
			if err != nil || !reused || !bytes.Equal(loaded.Cert.Raw, material.Cert.Raw) {
				t.Fatalf("restart did not recover the committed root: reused=%v err=%v", reused, err)
			}
			if _, err := os.Stat(failPath); err != nil {
				t.Fatalf("restart did not rebuild the missing compatibility view: %v", err)
			}
		})
	}
}

func TestRootPairSnapshotStagingFailureKeepsInitialStateEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.pem")
	material, err := GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	io := interceptionRootPairIO{
		write:   func(string, []byte, os.FileMode) error { return durablefile.ErrStagingFailed },
		syncDir: durablefile.SyncDir,
	}
	if err := writeInterceptionRootPairLocked(path, material, io); !errors.Is(err, durablefile.ErrStagingFailed) {
		t.Fatalf("initial snapshot failure was not surfaced: %v", err)
	}
	for _, name := range []string{path, NetworkExtensionLabTLSRootKeyPath(path), interceptionRootSnapshotPath(path)} {
		if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("initial failure published %q: %v", name, err)
		}
	}
}

func TestRootPairPostReplaceUncertaintyIsRecoveredOnRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.pem")
	material, err := GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	io := interceptionRootPairIO{
		write: func(name string, data []byte, mode os.FileMode) error {
			if err := durablefile.Write(name, data, mode); err != nil {
				return err
			}
			if name == interceptionRootSnapshotPath(path) {
				return durablefile.ErrReplacedNotFlushed
			}
			return nil
		},
		syncDir: func(string) error { return errors.New("injected directory sync failure") },
	}
	if err := writeInterceptionRootPairLocked(path, material, io); !errors.Is(err, durablefile.ErrReplacedNotFlushed) {
		t.Fatalf("uncertain durability was reported as success: %v", err)
	}
	loaded, reused, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(path, time.Now)
	if err != nil || !reused || !bytes.Equal(loaded.Cert.Raw, material.Cert.Raw) {
		t.Fatalf("the visible authoritative pair was not recovered: reused=%v err=%v", reused, err)
	}
}

func TestRootPairLegacyMigrationAndSnapshotCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.pem")
	material, err := GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, material.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(NetworkExtensionLabTLSRootKeyPath(path), material.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, reused, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(path, time.Now)
	if err != nil || !reused || !bytes.Equal(loaded.Cert.Raw, material.Cert.Raw) {
		t.Fatalf("valid legacy root did not migrate unchanged: reused=%v err=%v", reused, err)
	}
	snapshot := interceptionRootSnapshotPath(path)
	if err := validateNetworkExtensionLabTLSSecretFileMode(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshot, []byte(`{"version":1,"cert_pem":""}`), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(path, time.Now); err == nil {
		t.Fatal("corrupt authoritative snapshot silently fell back to legacy files")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("corrupt snapshot changed the legacy root")
	}
}

func TestRootPairRejectsBroadExistingKeyViewPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX key permissions are not represented by Windows file modes")
	}
	path := filepath.Join(t.TempDir(), "root.pem")
	material, err := GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteNetworkExtensionLabTLSPersistentRootMaterial(path, material); err != nil {
		t.Fatal(err)
	}
	keyPath := NetworkExtensionLabTLSRootKeyPath(path)
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(path, time.Now); err == nil {
		t.Fatal("broad existing private-key permissions were silently repaired")
	}
	info, err := os.Stat(keyPath)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("rejected key view was changed before the operator could inspect exposure")
	}
}

func TestRootPairCrossProcessLockPreventsSecondWriter(t *testing.T) {
	if os.Getenv("DSSE_ROOT_PAIR_LOCK_CHILD") == "1" {
		dir := os.Getenv("DSSE_ROOT_PAIR_LOCK_DIR")
		lock, err := agentupdate.LockDevice(filepath.Join(dir, ".dsse-interception-root.lock"))
		if err != nil {
			os.Exit(2)
		}
		defer lock.Release()
		if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0600); err != nil {
			os.Exit(3)
		}
		for i := 0; i < 500; i++ {
			if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Exit(4)
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRootPairCrossProcessLockPreventsSecondWriter$")
	cmd.Env = append(os.Environ(), "DSSE_ROOT_PAIR_LOCK_CHILD=1", "DSSE_ROOT_PAIR_LOCK_DIR="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.WriteFile(filepath.Join(dir, "release"), nil, 0600)
		if err := cmd.Wait(); err != nil {
			t.Errorf("lock-holder child: %v", err)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lock-holder did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	path := filepath.Join(dir, "root.pem")
	if _, _, err := loadOrCreateInterceptionRootPair(path, time.Now, ""); err == nil {
		t.Fatal("second process minted a root while the first held the pair lock")
	}
	if _, err := os.Stat(interceptionRootSnapshotPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("contended writer published material: %v", err)
	}
}

func TestRootPairConcurrentFirstStartUsesOneIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.pem")
	var wg sync.WaitGroup
	results := make(chan networkExtensionLabTLSRootMaterial, 2)
	errorsSeen := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			material, _, err := loadOrCreateInterceptionRootPair(path, time.Now, "")
			results <- material
			errorsSeen <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first []byte
	for material := range results {
		if first == nil {
			first = material.Cert.Raw
		} else if !bytes.Equal(first, material.Cert.Raw) {
			t.Fatal("two concurrent first starts minted different roots")
		}
	}
}

func TestRootPairDirectorySelectsSnapshotOnlyBeforeLegacy(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, NetworkExtensionLabTLSRootCertFilename)
	first, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, current)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(NetworkExtensionLabTLSRootKeyPath(current)); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, networkExtensionLabTLSRootCertLegacyFilenames[0])
	other, err := GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, other.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(NetworkExtensionLabTLSRootKeyPath(legacy), other.KeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restarted.rootCert.Raw, first.rootCert.Raw) {
		t.Fatal("snapshot-only current root was skipped for legacy material")
	}
}

func TestRootPairSealMigrationInterruptedAfterKeyViewKeepsIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.pem")
	material, err := GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteNetworkExtensionLabTLSPersistentRootMaterial(path, material); err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	SetInterceptionRootKEK(kek)
	t.Cleanup(func() { SetInterceptionRootKEK(nil) })
	sealedKey, err := maybeSealInterceptionKeyForDisk(material.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := newPersistedInterceptionRootPair(path, material.CertPEM, sealedKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeInterceptionRootSnapshotLocked(interceptionRootSnapshotPath(path), pair, productionInterceptionRootPairIO); err != nil {
		t.Fatal(err)
	}
	// Model an interrupted compatibility-view update: the new authority is
	// committed, the previous certificate view is damaged, and the key view
	// replacement succeeds before certificate repair fails.
	if err := os.WriteFile(path, []byte("damaged compatibility view"), 0600); err != nil {
		t.Fatal(err)
	}
	io := interceptionRootPairIO{
		write: func(name string, data []byte, mode os.FileMode) error {
			if name == path {
				return errors.New("injected certificate view failure")
			}
			return durablefile.Write(name, data, mode)
		},
		syncDir: durablefile.SyncDir,
	}
	if err := repairInterceptionRootViewsLocked(path, pair, io); err == nil {
		t.Fatal("interrupted seal migration was reported as complete")
	}
	keyDisk, err := os.ReadFile(NetworkExtensionLabTLSRootKeyPath(path))
	if err != nil || !isSealedInterceptionKeyPEM(keyDisk) {
		t.Fatal("committed key view was not sealed")
	}
	loaded, reused, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(path, time.Now)
	if err != nil || !reused || !bytes.Equal(loaded.Cert.Raw, material.Cert.Raw) {
		t.Fatalf("seal migration restart changed the root: reused=%v err=%v", reused, err)
	}
	SetInterceptionRootKEK(nil)
	if _, _, err := LoadNetworkExtensionLabTLSPersistentRootMaterial(path, time.Now); err == nil {
		t.Fatal("sealed authoritative snapshot loaded without its KEK")
	}
}
