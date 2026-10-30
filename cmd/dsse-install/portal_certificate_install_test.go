package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func installerPortalPair(t *testing.T, names []string, expired bool) (cert, key, root []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "disposable operator CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	root = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if expired {
		leaf.NotBefore = time.Now().Add(-2 * time.Hour)
		leaf.NotAfter = time.Now().Add(-time.Hour)
	}
	der, err = x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), root...)
	pk, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
	return
}

func TestInstallPortalCertificateValidatesBeforePublishing(t *testing.T) {
	dir := t.TempDir()
	input := t.TempDir()
	env := map[string]string{"DSSE_NODE_PORTAL_NAME": "portal-a.example.test", "DSSE_STEPUP_PORTAL_ORIGINS": "https://portal-a.example.test,https://portal-b.example.test,https://portal-c.example.test"}
	os.WriteFile(filepath.Join(dir, "deployment.env"), []byte(PlanEnvironmentFor("", env)), 0600)
	cert, key, root := installerPortalPair(t, []string{"portal-a.example.test", "portal-b.example.test", "portal-c.example.test"}, false)
	write := func(name string, data []byte) string {
		path := filepath.Join(input, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	certPath, keyPath, caPath := write("cert", cert), write("key", key), write("ca", root)
	if err := installPortalCertificate(dir, certPath, keyPath, caPath); err != nil {
		t.Fatal(err)
	}
	if result := verifyOneRegionThreeNodesPortalCertificate(dir, readDeploymentEnv(dir)); !result.ok {
		t.Fatal(result.note)
	}
	info, err := os.Stat(filepath.Join(dir, "clientless/tls.key"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("browser key permissions")
	}
	for _, mode := range []string{"wrong-key", "missing-san", "expired", "leaf-as-ca", "key-in-chain", "junk-in-ca"} {
		t.Run(mode, func(t *testing.T) {
			c, k, r := cert, key, root
			switch mode {
			case "wrong-key":
				_, k, _ = installerPortalPair(t, []string{"portal-a.example.test"}, false)
			case "missing-san":
				c, k, r = installerPortalPair(t, []string{"portal-a.example.test"}, false)
			case "expired":
				c, k, r = installerPortalPair(t, []string{"portal-a.example.test", "portal-b.example.test", "portal-c.example.test"}, true)
			case "leaf-as-ca":
				r = cert
			case "key-in-chain":
				c = append(append([]byte{}, cert...), key...)
			case "junk-in-ca":
				r = append([]byte("unexpected data\n"), root...)
			}
			if err := installPortalCertificate(dir, write("bad-cert", c), write("bad-key", k), write("bad-ca", r)); err == nil {
				t.Fatal("invalid browser material installed")
			}
			got, _ := os.ReadFile(filepath.Join(dir, "clientless/tls.crt"))
			if !bytes.Equal(got, cert) {
				t.Fatal("invalid input changed live certificate")
			}
			got, _ = os.ReadFile(filepath.Join(dir, "clientless/tls.key"))
			if !bytes.Equal(got, key) {
				t.Fatal("invalid input changed live key")
			}
		})
	}
}

func TestThreeRegionEdgeCertificateCoversOnlyItsOwnPortalOrigin(t *testing.T) {
	env := map[string]string{
		"DSSE_TOPOLOGY_PROFILE":      "three-regions-multi-edge",
		"DSSE_NODE_PORTAL_NAME":      "portal.region-b.example.test",
		"DSSE_STEPUP_PORTAL_ORIGINS": "https://portal.region-a.example.test,https://portal.region-b.example.test,https://portal.region-c.example.test",
	}
	names, err := portalCertificateNames(env)
	if err != nil || len(names) != 1 || names[0] != "portal.region-b.example.test" {
		t.Fatalf("regional Edge must serve only its own Portal origin: %v %v", names, err)
	}
	cert, key, root := installerPortalPair(t, names, false)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) || validatePortalPair(cert, key, env, pool) != nil {
		t.Fatal("valid regional browser certificate was rejected")
	}
	localCert, localKey, localRoot := installerPortalPair(t, []string{"portal.region-b.example.test"}, false)
	localPool := x509.NewCertPool()
	if !localPool.AppendCertsFromPEM(localRoot) {
		t.Fatal("fixture CA")
	}
	if err := validatePortalPair(localCert, localKey, env, localPool); err != nil {
		t.Fatal("browser certificate for only the owning Region was rejected:", err)
	}
	foreignCert, foreignKey, foreignRoot := installerPortalPair(t, []string{"portal.region-a.example.test"}, false)
	foreignPool := x509.NewCertPool()
	foreignPool.AppendCertsFromPEM(foreignRoot)
	if err := validatePortalPair(foreignCert, foreignKey, env, foreignPool); err == nil {
		t.Fatal("certificate missing the owning Region Portal was accepted")
	}
	missingOwn := map[string]string{
		"DSSE_TOPOLOGY_PROFILE":      "three-regions-multi-edge",
		"DSSE_NODE_PORTAL_NAME":      "portal.region-b.example.test",
		"DSSE_STEPUP_PORTAL_ORIGINS": "https://portal.region-a.example.test,https://portal.region-c.example.test",
	}
	if _, err := portalCertificateNames(missingOwn); err == nil {
		t.Fatal("signed origin list missing the owning Region was accepted")
	}
}

func TestSharedFleetLaunchersExportBrowserCertificateContract(t *testing.T) {
	for _, p := range []*Plan{threeNodesOneRegionPlan(), threeRegionsMultiEdgePlan(), oneRegionMultiEdgePlan()} {
		work := t.TempDir()
		path := filepath.Join(work, "plan.json")
		raw, _ := json.Marshal(p)
		os.WriteFile(path, raw, 0600)
		dir := filepath.Join(work, "deployment")
		installFromPlan(t, path, dir)
		f, err := os.OpenFile(filepath.Join(dir, "deployment.env"), os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString("\nDSSE_ARCHIVE_ENDPOINT='archive.example.test:443'\nDSSE_ARCHIVE_BUCKET='fixture'\nDSSE_ARCHIVE_AUTH_MODE='static'\nDSSE_ARCHIVE_ACCESS_KEY='fixture'\nDSSE_ARCHIVE_SECRET_KEY='fixture'\nDSSE_ARCHIVE_WEBHOOK_URL='https://alerts.example.test/dsse'\n")
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range p.machines() {
			env, err := p.MachineEnvironment(m.Name)
			if err != nil || env[stepUpPortalCertEnvKey] != "operator" {
				t.Fatalf("%s did not share browser trust contract", m.Name)
			}
		}
		capture := filepath.Join(work, "capture")
		os.WriteFile(capture, []byte("#!/bin/sh\nprintf '%s' \"${DSSE_STEP_UP_PORTAL_CERTIFICATE-unset}\"\n"), 0700)
		for _, script := range []string{"start-control-plane.sh", "start-edge.sh"} {
			cmd := exec.Command("/bin/sh", filepath.Join(dir, script))
			cmd.Env = append(os.Environ(), "DSSE_EDGE_BINARY="+capture, "DSSE_POSTGRES_DSN=postgres://fixture.invalid/test", "DSSE_MIGRATION_DIR="+dir, "DSSE_CP_STATE_DIR="+dir, "DSSE_CONTROL_PLANE=https://fixture.invalid", "DSSE_CONTROL_PLANE_DATA=https://fixture.invalid")
			out, err := cmd.CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != "operator" {
				t.Fatalf("%s did not export operator trust: %v %s", script, err, out)
			}
		}
	}
}

func TestEdgeLauncherPassesPortalTrustOnlyAsACertificateCheckArgument(t *testing.T) {
	dir := installerFixture(t, threeNodesOneRegionPlan())
	if err := os.WriteFile(filepath.Join(dir, "clientless/trust.pem"), []byte("fixture-input"), 0600); err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(t.TempDir(), "capture")
	if err := os.WriteFile(capture, []byte("#!/bin/sh\nprintf 'ROOTS=%s\\n' \"${SSL_CERT_FILE-unset}\"\nprintf 'ARG=%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", "operator-system-trust-input")
	cmd := exec.Command("/bin/sh", filepath.Join(dir, "start-edge.sh"))
	cmd.Env = append(os.Environ(), "DSSE_EDGE_BINARY="+capture, "DSSE_CONTROL_PLANE=https://authority.invalid", "DSSE_CONTROL_PLANE_DATA=https://authority.invalid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("launcher failed: %v %s", err, out)
	}
	if !strings.Contains(string(out), "ROOTS=operator-system-trust-input\n") || !strings.Contains(string(out), "ARG=-clientless-tls-ca="+filepath.Join(dir, "clientless/trust.pem")+"\n") {
		t.Fatalf("Portal trust widened process roots or was not checked: %s", out)
	}
}
