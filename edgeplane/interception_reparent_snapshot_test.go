package edgeplane

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/durablefile"
)

func reparentSnapshotCandidate(t *testing.T, name string, signer *ecdsa.PrivateKey) ([]byte, []byte) {
	t.Helper()
	root, rootKey := mintReparentCA(t, name, nil, nil)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name + " Issuer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, signer.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestReparentFailedSnapshotWriteKeepsPreviousPairAndLiveIssuer(t *testing.T) {
	self, signer := mintReparentCA(t, "Edge", nil, nil)
	interception := newTestInterceptionForReparent(t, self, signer)
	dir := t.TempDir()
	oldRoot, oldInter := reparentSnapshotCandidate(t, "Old", signer)
	if err := AdoptReparentedIntermediate(interception, oldRoot, oldInter, dir); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, reparentedSnapshotFileName))
	if err != nil {
		t.Fatal(err)
	}
	newRoot, newInter := reparentSnapshotCandidate(t, "New", signer)
	err = adoptReparentedIntermediateWithIO(interception, newRoot, newInter, dir, reparentSnapshotIO{
		write:   func(string, []byte, os.FileMode) error { return errors.New("injected before replacement") },
		syncDir: durablefile.SyncDir,
	})
	if err == nil {
		t.Fatal("expected write failure")
	}
	after, err := os.ReadFile(filepath.Join(dir, reparentedSnapshotFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || interception.rootCert.Subject.CommonName != "Old" {
		t.Fatal("failed snapshot write changed the previous pair or live issuer")
	}
}

func TestReparentReplacedNotFlushedRetriesAndAdoptsSamePair(t *testing.T) {
	self, signer := mintReparentCA(t, "Edge", nil, nil)
	interception := newTestInterceptionForReparent(t, self, signer)
	dir := t.TempDir()
	root, inter := reparentSnapshotCandidate(t, "New", signer)
	syncCalls := 0
	err := adoptReparentedIntermediateWithIO(interception, root, inter, dir, reparentSnapshotIO{
		write: func(path string, data []byte, mode os.FileMode) error {
			if err := durablefile.Write(path, data, mode); err != nil {
				return err
			}
			return durablefile.ErrReplacedNotFlushed
		},
		syncDir: func(string) error { syncCalls++; return nil },
	})
	if err != nil || syncCalls != 1 || interception.rootCert.Subject.CommonName != "New" {
		t.Fatalf("visible replacement and successful flush must adopt candidate: err=%v syncs=%d", err, syncCalls)
	}
	restarted := newTestInterceptionForReparent(t, self, signer)
	ReapplyPersistedReparent(restarted, dir)
	if restarted.rootCert.Subject.CommonName != "New" {
		t.Fatal("restart did not restore the new pair")
	}
}

func TestReparentReplacedUnflushedReportsDegradedWithoutLiveDiskSplit(t *testing.T) {
	self, signer := mintReparentCA(t, "Edge", nil, nil)
	interception := newTestInterceptionForReparent(t, self, signer)
	dir := t.TempDir()
	root, inter := reparentSnapshotCandidate(t, "New", signer)
	err := adoptReparentedIntermediateWithIO(interception, root, inter, dir, reparentSnapshotIO{
		write: func(path string, data []byte, mode os.FileMode) error {
			if err := durablefile.Write(path, data, mode); err != nil {
				return err
			}
			return durablefile.ErrReplacedNotFlushed
		},
		syncDir: func(string) error { return errors.New("injected flush failure") },
	})
	if !errors.Is(err, durablefile.ErrReplacedNotFlushed) || interception.rootCert.Subject.CommonName != "New" {
		t.Fatalf("must report uncertain durability and reflect visible candidate: %v", err)
	}
	if _, ok := interception.InterceptionIntermediateStatus()["reparent_restore_failed"]; !ok {
		t.Fatal("uncertain durability must mark readiness degraded")
	}
	restarted := newTestInterceptionForReparent(t, self, signer)
	ReapplyPersistedReparent(restarted, dir)
	if restarted.rootCert.Subject.CommonName != "New" {
		t.Fatal("visible snapshot does not restore candidate")
	}
}

func TestReparentConcurrentAdoptsKeepLiveAndSnapshotOrder(t *testing.T) {
	self, signer := mintReparentCA(t, "Edge", nil, nil)
	interception := newTestInterceptionForReparent(t, self, signer)
	dir := t.TempDir()
	firstRoot, firstInter := reparentSnapshotCandidate(t, "First", signer)
	secondRoot, secondInter := reparentSnapshotCandidate(t, "Second", signer)
	entered, release := make(chan struct{}), make(chan struct{})
	firstErr := make(chan error, 1)
	go func() {
		firstErr <- adoptReparentedIntermediateWithIO(interception, firstRoot, firstInter, dir, reparentSnapshotIO{
			write: func(path string, data []byte, mode os.FileMode) error {
				close(entered)
				<-release
				return durablefile.Write(path, data, mode)
			}, syncDir: durablefile.SyncDir,
		})
	}()
	<-entered
	var wg sync.WaitGroup
	wg.Add(1)
	var secondErr error
	go func() {
		defer wg.Done()
		secondErr = AdoptReparentedIntermediate(interception, secondRoot, secondInter, dir)
	}()
	close(release)
	if err := <-firstErr; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if secondErr != nil {
		t.Fatal(secondErr)
	}
	restarted := newTestInterceptionForReparent(t, self, signer)
	ReapplyPersistedReparent(restarted, dir)
	if restarted.rootCert.Subject.CommonName != "Second" || interception.rootCert.Subject.CommonName != "Second" {
		t.Fatal("serialized adoption left live and durable pairs out of order")
	}
}

func TestReparentMalformedSnapshotIsDegraded(t *testing.T) {
	self, signer := mintReparentCA(t, "Edge", nil, nil)
	interception := newTestInterceptionForReparent(t, self, signer)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, reparentedSnapshotFileName), []byte(`{"version":1,"root_pem":""}`), 0600); err != nil {
		t.Fatal(err)
	}
	ReapplyPersistedReparent(interception, dir)
	if _, ok := interception.InterceptionIntermediateStatus()["reparent_restore_failed"]; !ok {
		t.Fatal("malformed persisted snapshot must be visible as degraded")
	}
}
