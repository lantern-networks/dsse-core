package edgeplane

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func reparentFileBackedRootCandidate(t *testing.T, engine *NetworkExtensionLabTLSInterception) ([]byte, []byte) {
	t.Helper()
	central, centralKey := mintReparentCA(t, "Central Export Root", nil, nil)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200), Subject: pkix.Name{CommonName: "File Signer Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, interTmpl, central,
		engine.rootRegistry.DefaultProvider().Signer().Public(), centralKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: central.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestFileBackedRootReparentKeepsSignerPairAndPublishesSeparateAnchor(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "signer.pem")
	engine, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, certPath)
	if err != nil {
		t.Fatal(err)
	}
	certBefore, keyBefore := persistentRootPairHashes(t, certPath)
	export := NetworkExtensionLabTLSActiveAnchorExportPath(certPath)
	if engine.ActiveAnchorExportPath() != export || export == certPath || export == NetworkExtensionLabTLSRootKeyPath(certPath) {
		t.Fatal("public anchor export aliases signer material")
	}
	if err := engine.PublishActiveAnchorExport(); err != nil {
		t.Fatal(err)
	}
	rootPEM, interPEM := reparentFileBackedRootCandidate(t, engine)
	stateDir := t.TempDir()
	if err := AdoptReparentedIntermediate(engine, rootPEM, interPEM, stateDir); err != nil {
		t.Fatal(err)
	}
	certAfter, keyAfter := persistentRootPairHashes(t, certPath)
	if certAfter != certBefore || keyAfter != keyBefore {
		t.Fatal("re-parent rewrote signer certificate or key")
	}
	active, err := os.ReadFile(export)
	if err != nil || !bytes.Equal(active, rootPEM) {
		t.Fatal("separate export does not contain the active anchor")
	}
	restarted, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, certPath)
	if err != nil {
		t.Fatal(err)
	}
	// Construction must not roll back an already published re-parented anchor
	// if the process dies before replaying the durable re-parent snapshot.
	beforeReplay, err := os.ReadFile(export)
	if err != nil || !bytes.Equal(beforeReplay, rootPEM) {
		t.Fatal("constructor rolled the public anchor back before replay")
	}
	ReapplyPersistedReparent(restarted, stateDir)
	if err := restarted.PublishActiveAnchorExport(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restarted.RootCertificatePEM(), rootPEM) {
		t.Fatal("boot did not restore the re-parented anchor")
	}
	active, err = os.ReadFile(restarted.ActiveAnchorExportPath())
	if err != nil || !bytes.Equal(active, rootPEM) {
		t.Fatal("boot did not restore the separate export")
	}
	certAfter, keyAfter = persistentRootPairHashes(t, certPath)
	if certAfter != certBefore || keyAfter != keyBefore {
		t.Fatal("boot changed signer material")
	}
}

func TestFileBackedRootReparentExportFailureIsDegradedAndRecoverable(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "signer.pem")
	engine, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.PublishActiveAnchorExport(); err != nil {
		t.Fatal(err)
	}
	certBefore, keyBefore := persistentRootPairHashes(t, certPath)
	export := engine.ActiveAnchorExportPath()
	engine.rootCACertOutPath = filepath.Join(certPath, "unwritable-anchor.pem")
	rootPEM, interPEM := reparentFileBackedRootCandidate(t, engine)
	stateDir := t.TempDir()
	if err := AdoptReparentedIntermediate(engine, rootPEM, interPEM, stateDir); err == nil {
		t.Fatal("failed export was reported as completed re-parent")
	}
	if _, ok := engine.InterceptionIntermediateStatus()["reparent_restore_failed"]; !ok {
		t.Fatal("failed export did not surface degraded status")
	}
	if certAfter, keyAfter := persistentRootPairHashes(t, certPath); certAfter != certBefore || keyAfter != keyBefore {
		t.Fatal("failed export damaged signer pair")
	}
	engine.rootCACertOutPath = export
	restarted, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, certPath)
	if err != nil {
		t.Fatal(err)
	}
	ReapplyPersistedReparent(restarted, stateDir)
	if err := restarted.PublishActiveAnchorExport(); err != nil {
		t.Fatal(err)
	}
	if _, failed := restarted.InterceptionIntermediateStatus()["reparent_restore_failed"]; failed {
		t.Fatal("valid durable re-parent did not clear degraded export after recovery")
	}
	active, err := os.ReadFile(export)
	if err != nil || !bytes.Equal(active, rootPEM) {
		t.Fatal("recovery did not publish the active anchor")
	}
}

func TestFileBackedRootRefusesPublicExportThroughSignerDirectoryAlias(t *testing.T) {
	dir := t.TempDir()
	signerDir := filepath.Join(dir, "signer")
	if err := os.Mkdir(signerDir, 0700); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(signerDir, "root.pem")
	engine, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, certPath)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(signerDir, alias); err != nil {
		t.Fatal(err)
	}
	beforeCert, beforeKey := persistentRootPairHashes(t, certPath)
	for _, privateName := range []string{filepath.Base(certPath), filepath.Base(NetworkExtensionLabTLSRootKeyPath(certPath)), filepath.Base(interceptionRootSnapshotPath(certPath))} {
		if err := engine.ConfigureActiveAnchorExport(filepath.Join(alias, privateName)); err == nil {
			t.Fatalf("public export accepted signer alias %q", privateName)
		}
	}
	afterCert, afterKey := persistentRootPairHashes(t, certPath)
	if afterCert != beforeCert || afterKey != beforeKey {
		t.Fatal("alias refusal changed signer material")
	}
}

func TestActiveAnchorExportInputAliasValidationDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	engine, err := NewNetworkExtensionLabTLSInterception([]string{"example.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "source.pem")
	if err := os.WriteFile(input, engine.RootCertificatePEM(), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "source-alias.pem")
	if err := os.Symlink(input, alias); err != nil {
		t.Fatal(err)
	}
	if err := engine.ConfigureActiveAnchorExport(alias, input); err == nil {
		t.Fatal("configured export over a source certificate symlink")
	}
	if got := engine.ActiveAnchorExportPath(); got != "" {
		t.Fatalf("refused export was recorded: %q", got)
	}
	export := filepath.Join(dir, "active.pem")
	if err := engine.ConfigureActiveAnchorExport(export, input); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(export)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.ValidateActiveAnchorExportInputs(export); err == nil {
		t.Fatal("recorded export alias was not rejected")
	}
	after, err := os.ReadFile(export)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read-only validation changed export")
	}
}

func TestPrepareActiveAnchorExportDoesNotPublishBeforeRestore(t *testing.T) {
	engine, err := NewNetworkExtensionLabTLSInterception([]string{"example.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "active.pem")
	if err := engine.PrepareActiveAnchorExport(path); err != nil {
		t.Fatal(err)
	}
	if engine.ActiveAnchorExportPath() != path {
		t.Fatal("prepared output was not recorded")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("preparation published before restore: %v", err)
	}
	if err := engine.PublishActiveAnchorExport(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, engine.RootCertificatePEM()) {
		t.Fatal("first publish did not write the active anchor")
	}
}

func TestPublishActiveAnchorExportRefusesExistingDifferentOrMalformedAnchor(t *testing.T) {
	engine, err := NewNetworkExtensionLabTLSInterception([]string{"example.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "active.pem")
	if err := engine.PrepareActiveAnchorExport(path); err != nil {
		t.Fatal(err)
	}
	other, err := GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	for name, previous := range map[string][]byte{
		"different": other.CertPEM,
		"malformed": []byte("existing distribution is not a certificate"),
		"appended":  append(bytes.Clone(engine.RootCertificatePEM()), []byte("PRIVATE DATA")...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, previous, 0600); err != nil {
				t.Fatal(err)
			}
			if err := engine.PublishActiveAnchorExport(); err == nil {
				t.Fatal("existing unverified anchor was replaced")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, previous) {
				t.Fatal("refused publication changed the existing anchor")
			}
		})
	}
}

func TestPublishActiveAnchorExportKeepsMatchingExistingCertificate(t *testing.T) {
	engine, err := NewNetworkExtensionLabTLSInterception([]string{"example.com"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "active.pem")
	if err := engine.PrepareActiveAnchorExport(path); err != nil {
		t.Fatal(err)
	}
	// Matching DER may have different PEM whitespace. Publishing must neither
	// reject the valid existing trust anchor nor rewrite its original bytes.
	previous := bytes.ReplaceAll(engine.RootCertificatePEM(), []byte("\n"), []byte("\r\n"))
	if err := os.WriteFile(path, previous, 0600); err != nil {
		t.Fatal(err)
	}
	if err := engine.PublishActiveAnchorExport(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, previous) {
		t.Fatal("matching anchor was rewritten")
	}
}

func TestFileBackedRootMissingReparentSnapshotRefusesAnchorRollback(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "signer.pem")
	engine, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.PublishActiveAnchorExport(); err != nil {
		t.Fatal(err)
	}
	newAnchor, intermediate := reparentFileBackedRootCandidate(t, engine)
	stateDir := t.TempDir()
	if err := AdoptReparentedIntermediate(engine, newAnchor, intermediate, stateDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(stateDir, reparentedSnapshotFileName)); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewNetworkExtensionLabTLSInterceptionWithPersistentRoot([]string{"example.com"}, time.Now, certPath)
	if err != nil {
		t.Fatal(err)
	}
	ReapplyPersistedReparent(restarted, stateDir)
	if err := restarted.PublishActiveAnchorExport(); err == nil {
		t.Fatal("missing durable adoption silently rolled the public anchor back")
	}
	actual, err := os.ReadFile(restarted.ActiveAnchorExportPath())
	if err != nil || !bytes.Equal(actual, newAnchor) {
		t.Fatal("failed restart changed the previously distributed anchor")
	}
}
