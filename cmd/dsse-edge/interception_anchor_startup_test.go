package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

func startupInterceptionFixture(t *testing.T) *edgeplane.NetworkExtensionLabTLSInterception {
	t.Helper()
	engine, err := edgeplane.NewNetworkExtensionLabTLSInterceptionWithPersistentRoot(
		[]string{"example.com"}, time.Now, filepath.Join(t.TempDir(), "signer.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestInterceptionStartupPublishesOnlyAfterRestore(t *testing.T) {
	engine := startupInterceptionFixture(t)
	if _, err := os.Stat(engine.ActiveAnchorExportPath()); !os.IsNotExist(err) {
		t.Fatalf("constructor published before restoration: %v", err)
	}
	if err := restoreAndPublishInterceptionAnchor(engine, t.TempDir(), ""); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(engine.ActiveAnchorExportPath())
	if err != nil || !bytes.Equal(got, engine.RootCertificatePEM()) {
		t.Fatal("startup did not publish the restored active certificate")
	}
}

func TestInterceptionStartupRejectsCorruptRestoreWithoutReplacingExport(t *testing.T) {
	engine := startupInterceptionFixture(t)
	previous := []byte("existing export must remain untouched on failed restore")
	if err := os.WriteFile(engine.ActiveAnchorExportPath(), previous, 0600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "interception_reparent_pair.json"), []byte(`{"version":1`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreAndPublishInterceptionAnchor(engine, dir, ""); err == nil || !strings.Contains(err.Error(), "could not be restored") {
		t.Fatalf("corrupt durable authority permitted startup: %v", err)
	}
	got, err := os.ReadFile(engine.ActiveAnchorExportPath())
	if err != nil || !bytes.Equal(got, previous) {
		t.Fatal("failed restore overwrote existing distribution material")
	}
}

func TestInterceptionStartupRejectsFailedExport(t *testing.T) {
	engine := startupInterceptionFixture(t)
	if err := os.Mkdir(engine.ActiveAnchorExportPath(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := restoreAndPublishInterceptionAnchor(engine, t.TempDir(), ""); err == nil {
		t.Fatal("unwritable public export permitted startup")
	}
}

func TestInterceptionStartupProviderExportIsCertificateOnly(t *testing.T) {
	material, err := edgeplane.GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := edgeplane.NewNetworkExtensionLabTLSInterceptionWithProvider(
		[]string{"example.com"}, time.Now, edgeplane.NewFileInterceptionRootProvider(material))
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "public.pem")
	if err := restoreAndPublishInterceptionAnchor(engine, t.TempDir(), output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, material.CertPEM) || bytes.Contains(got, []byte("PRIVATE KEY")) {
		t.Fatal("provider export did not contain only the active certificate")
	}
}

func TestInterceptionStartupRefusesInputAliasBeforeExport(t *testing.T) {
	engine := startupInterceptionFixture(t)
	path := engine.ActiveAnchorExportPath()
	previous := []byte("input material must not be overwritten")
	if err := os.WriteFile(path, previous, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreAndPublishInterceptionAnchor(engine, t.TempDir(), "", path); err == nil {
		t.Fatal("export aliasing input material permitted startup")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, previous) {
		t.Fatal("input material changed on rejected startup")
	}
}

func TestInterceptionStartupProviderCannotOverwriteSource(t *testing.T) {
	material, err := edgeplane.GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := edgeplane.NewNetworkExtensionLabTLSInterceptionWithProvider(
		[]string{"example.com"}, time.Now, edgeplane.NewFileInterceptionRootProvider(material))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "source.pem")
	if err := os.WriteFile(path, material.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreAndPublishInterceptionAnchor(engine, t.TempDir(), path, path); err == nil {
		t.Fatal("provider output aliasing provider input permitted startup")
	}
}

func TestInterceptionStartupCannotRollBackExportWithoutRestoreState(t *testing.T) {
	for _, provider := range []bool{false, true} {
		for _, state := range []string{"empty", "missing", "without-snapshot"} {
			name := state
			if provider {
				name = "provider-" + name
			}
			t.Run(name, func(t *testing.T) {
				engine := startupInterceptionFixture(t)
				export := engine.ActiveAnchorExportPath()
				providerExport := ""
				if provider {
					material, err := edgeplane.GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
					if err != nil {
						t.Fatal(err)
					}
					engine, err = edgeplane.NewNetworkExtensionLabTLSInterceptionWithProvider(
						[]string{"example.com"}, time.Now, edgeplane.NewFileInterceptionRootProvider(material))
					if err != nil {
						t.Fatal(err)
					}
					export = filepath.Join(t.TempDir(), "active.pem")
					providerExport = export
				}
				previous := startupInterceptionFixture(t).RootCertificatePEM()
				if err := os.WriteFile(export, previous, 0600); err != nil {
					t.Fatal(err)
				}
				dir := ""
				if state != "empty" {
					dir = t.TempDir()
					if state == "missing" {
						dir = filepath.Join(dir, "absent")
					}
				}
				if err := restoreAndPublishInterceptionAnchor(engine, dir, providerExport); err == nil {
					t.Fatal("different published authority accepted without durable restoration")
				}
				got, err := os.ReadFile(export)
				if err != nil || !bytes.Equal(got, previous) {
					t.Fatal("startup rolled back the published authority")
				}
			})
		}
	}
}

func TestInterceptionStartupCannotExportOverRestoreSnapshot(t *testing.T) {
	engine := startupInterceptionFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "interception_reparent_pair.json")
	previous := []byte("durable state must not be replaced")
	if err := os.WriteFile(path, previous, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreAndPublishInterceptionAnchor(engine, dir, path); err == nil || !strings.Contains(err.Error(), "prepare public") {
		t.Fatalf("output alias not rejected before restore: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, previous) {
		t.Fatal("durable state changed on rejected startup")
	}
}

func TestInterceptionStartupProviderRestoresBeforePublishing(t *testing.T) {
	material, err := edgeplane.GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	provider := edgeplane.NewFileInterceptionRootProvider(material)
	engine, err := edgeplane.NewNetworkExtensionLabTLSInterceptionWithProvider([]string{"example.com"}, time.Now, provider)
	if err != nil {
		t.Fatal(err)
	}
	central, err := edgeplane.GenerateNetworkExtensionLabTLSRootMaterial(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	centralProvider := edgeplane.NewFileInterceptionRootProvider(central)
	centralCert, err := edgeplane.ParseInterceptionCertPEM(central.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(500), Subject: pkix.Name{CommonName: "Startup Intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, centralCert, provider.Signer().Public(), centralProvider.Signer())
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	if err := edgeplane.AdoptReparentedIntermediate(engine, central.CertPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), stateDir); err != nil {
		t.Fatal(err)
	}
	restarted, err := edgeplane.NewNetworkExtensionLabTLSInterceptionWithProvider([]string{"example.com"}, time.Now, edgeplane.NewFileInterceptionRootProvider(material))
	if err != nil {
		t.Fatal(err)
	}
	export := filepath.Join(t.TempDir(), "active.pem")
	// A valid durable restore is allowed to repair a stale public export. A
	// publish before restore, or recording its path too late, would reject this.
	if err := os.WriteFile(export, material.CertPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restoreAndPublishInterceptionAnchor(restarted, stateDir, export); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(export)
	if err != nil || !bytes.Equal(got, central.CertPEM) || !bytes.Equal(restarted.RootCertificatePEM(), central.CertPEM) {
		t.Fatal("provider startup did not restore and publish the durable active authority")
	}
}
