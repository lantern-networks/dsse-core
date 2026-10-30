package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

	"github.com/lantern-networks/dsse-core/deploymentcrl"
)

func TestReplicaUnitsUseOnlyPublicMaterialAndIndependentCDPs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "public")
	unitsDir := filepath.Join(t.TempDir(), "units")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test deployment"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	root := makeReplicaUnitCert(t, rootTemplate, rootTemplate, rootKey, rootKey)
	writeReplicaCert(t, filepath.Join(dir, "root.crt"), root)
	sourceOrigin, replicaOrigin := "http://signer-crl.example.test", "http://replica-crl.example.test"
	rootPoints, err := deploymentcrl.DistributionPoints([]string{sourceOrigin, replicaOrigin}, root, root)
	if err != nil {
		t.Fatal(err)
	}
	issuers := []*x509.Certificate{root}
	for i, spec := range issuerFiles[1:] {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: spec.cert},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(20 * 24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			CRLDistributionPoints: rootPoints,
		}
		cert := makeReplicaUnitCert(t, template, root, key, rootKey)
		issuers = append(issuers, cert)
		writeReplicaCert(t, filepath.Join(dir, spec.cert), cert)
	}
	if err := writeReplicaServiceUnits(dir, unitsDir, sourceOrigin, replicaOrigin, root, issuers); err != nil {
		t.Fatal(err)
	}
	base := "dsse-crl-" + deploymentcrl.Fingerprint(root)[:12]
	replicate, err := os.ReadFile(filepath.Join(unitsDir, base+"-replicate.service"))
	if err != nil {
		t.Fatal(err)
	}
	serve, err := os.ReadFile(filepath.Join(unitsDir, base+"-serve.service"))
	if err != nil {
		t.Fatal(err)
	}
	timer, err := os.ReadFile(filepath.Join(unitsDir, base+"-replicate.timer"))
	if err != nil {
		t.Fatal(err)
	}
	install, err := os.ReadFile(filepath.Join(unitsDir, "install-deployment-crl-replica-services.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"User=" + base, "-mode replicate", "-source-origin " + systemdLiteral(sourceOrigin),
		"ReadWritePaths=" + systemdLiteral(filepath.Join(dir, "deployment-crl")),
		"ProtectSystem=strict", "-mode replica-ready",
	} {
		if !strings.Contains(string(replicate), want) {
			t.Errorf("replicator missing %q", want)
		}
	}
	if !strings.Contains(string(serve), "-mode serve -origins "+systemdLiteral(replicaOrigin)) ||
		!strings.Contains(string(serve), "-listen 127.0.0.1:18081") ||
		strings.Contains(string(serve), "ReadWritePaths=") ||
		strings.Contains(string(serve), "-mode renew") {
		t.Fatal("publisher is not an independent, read-only keyless service")
	}
	if !strings.Contains(string(timer), "OnUnitActiveSec=10min") ||
		!strings.Contains(string(install), "systemctl start "+base+"-replicate.service") ||
		!strings.Contains(string(install), "-mode replica-ready") ||
		!strings.Contains(string(install), "systemctl enable --now "+base+"-replicate.timer "+base+"-serve.service") {
		t.Fatal("activation does not gate publication on a complete first replication")
	}
	if err := os.WriteFile(filepath.Join(dir, "root.key"), []byte("must not be copied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeReplicaServiceUnits(dir, unitsDir, sourceOrigin, replicaOrigin, root, issuers); err == nil {
		t.Fatal("replica accepted authority material in its public directory")
	}
}

func makeReplicaUnitCert(t *testing.T, template, parent *x509.Certificate, key, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func writeReplicaCert(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
}
