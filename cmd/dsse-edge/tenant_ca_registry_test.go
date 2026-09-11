package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	tenantca "github.com/lantern-networks/dsse-core/tenantca"
)

type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	pemPath string
}

func makeTestCA(t *testing.T, dir, cn string, serial int64) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	p := filepath.Join(dir, cn+".pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key, pemPath: p}
}

// leafSignedBy issues a client leaf cert signed by ca and returns its verified chains against pool.
func leafSignedBy(t *testing.T, ca testCA, cn string, pool *x509.CertPool) [][]*x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return nil // not trusted by the pool
	}
	return chains
}

// writeRegistry builds the registry with the JSON encoder rather than by concatenating strings. The paths it
// embeds come from t.TempDir, and on Windows those contain backslashes — `C:\Users\...` pasted into a JSON
// string literal is not the path, it is an invalid escape sequence (`\U`), and every test using this helper
// failed at parse time with an error about the registry rather than about its own subject.
func writeRegistry(t *testing.T, dir string, entries map[string]string) string {
	t.Helper()
	type tenantEntry struct {
		TenantID string `json:"tenant_id"`
		CAFile   string `json:"ca_file"`
	}
	reg := struct {
		Tenants []tenantEntry `json:"tenants"`
	}{}
	for tid, caPath := range entries {
		reg.Tenants = append(reg.Tenants, tenantEntry{TenantID: tid, CAFile: caPath})
	}
	sb, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "registry.json")
	if err := os.WriteFile(p, sb, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTenantCARegistryIsolation(t *testing.T) {
	dir := t.TempDir()
	caA := makeTestCA(t, dir, "tenant-A-CA", 1)
	caB := makeTestCA(t, dir, "tenant-B-CA", 2)
	caUnreg := makeTestCA(t, dir, "unregistered-CA", 3)

	regPath := writeRegistry(t, dir, map[string]string{
		"tenant_a": caA.pemPath,
		"tenant_b": caB.pemPath,
	})
	reg, err := tenantca.LoadTenantCARegistry(regPath)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	if reg.TenantCount != 2 {
		t.Fatalf("expected 2 tenants, got %d", reg.TenantCount)
	}

	t.Run("A's cert resolves to tenant_a", func(t *testing.T) {
		chains := leafSignedBy(t, caA, "dev-a1", reg.Pool)
		if chains == nil {
			t.Fatal("A's cert should verify against the registry pool")
		}
		tid, ok := reg.TenantForVerifiedChains(chains)
		if !ok || tid != "tenant_a" {
			t.Fatalf("expected tenant_a, got %q ok=%v", tid, ok)
		}
	})

	t.Run("B's cert resolves to tenant_b (never A)", func(t *testing.T) {
		chains := leafSignedBy(t, caB, "dev-b1", reg.Pool)
		if chains == nil {
			t.Fatal("B's cert should verify against the registry pool")
		}
		tid, ok := reg.TenantForVerifiedChains(chains)
		if !ok || tid != "tenant_b" {
			t.Fatalf("expected tenant_b, got %q ok=%v", tid, ok)
		}
		if tid == "tenant_a" {
			t.Fatal("ISOLATION VIOLATION: B's cert resolved to tenant_a")
		}
	})

	t.Run("unregistered CA's cert does not verify (not admitted)", func(t *testing.T) {
		chains := leafSignedBy(t, caUnreg, "dev-x", reg.Pool)
		if chains != nil {
			t.Fatal("a cert from an unregistered CA must NOT verify against the registry pool")
		}
	})

	t.Run("CA shared by two tenants fails to load (isolation guard)", func(t *testing.T) {
		bad := writeRegistry(t, dir, map[string]string{"tenant_a": caA.pemPath})
		// hand-craft a registry where the SAME CA is under two tenant ids
		// Same reason as writeRegistry: the CA path must be ENCODED into the JSON, not pasted into it.
		dupJSON, err := json.Marshal(map[string]any{"tenants": []map[string]string{
			{"tenant_id": "t1", "ca_file": caA.pemPath},
			{"tenant_id": "t2", "ca_file": caA.pemPath},
		}})
		if err != nil {
			t.Fatal(err)
		}
		dup := filepath.Join(dir, "dup.json")
		_ = os.WriteFile(dup, dupJSON, 0o600)
		if _, err := tenantca.LoadTenantCARegistry(dup); err == nil {
			t.Fatal("a CA shared across tenants must fail to load")
		}
		_ = bad
	})
}
