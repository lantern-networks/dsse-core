package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/certreload"
	"github.com/lantern-networks/dsse-core/configversion"
	"github.com/lantern-networks/dsse-core/durablefile"
)

func rotationRecoveryPair(t *testing.T, serial int64) (string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "node.test"}, DNSNames: []string{"node.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}
func rotationRecoveryFiles(t *testing.T) (string, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	c, k := rotationRecoveryPair(t, 1)
	cp, kp := filepath.Join(dir, "node.crt"), filepath.Join(dir, "node.key")
	if err := os.WriteFile(cp, []byte(c), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, []byte(k), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := certreload.NewReloadableCert(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	old := certreload.Registered()
	certreload.SetRegistryForTest([]*certreload.ReloadableCert{r})
	t.Cleanup(func() { certreload.SetRegistryForTest(old) })
	return cp, kp, c, k
}
func TestCertificateKeyWriteRefusalKeepsRestartablePair(t *testing.T) {
	cp, kp, oldCert, oldKey := rotationRecoveryFiles(t)
	c, k := rotationRecoveryPair(t, 2)
	// A directory at the key path is a deterministic write failure even as root.
	if err := os.Remove(kp); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(kp, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := rotateNamedCert("node", c, k, time.Now()); err == nil {
		t.Fatal("key write should fail")
	}
	got, err := os.ReadFile(cp)
	if err != nil || string(got) != oldCert {
		t.Fatal("certificate changed before rejected key write")
	}
	if err := os.Remove(kp); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(kp, []byte(oldKey), 0600)
	if _, err := tls.LoadX509KeyPair(cp, kp); err != nil {
		t.Fatal("old pair is not restartable")
	}
}
func TestFirstCertificateReplacementRetainsOriginalForRollback(t *testing.T) {
	cp, kp, oldCert, oldKey := rotationRecoveryFiles(t)
	c, k := rotationRecoveryPair(t, 2)
	admin := func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }
	store := configversion.NewMemoryStore()
	cpMux := http.NewServeMux()
	registerConfigVersionRoutes(cpMux, admin, serverConfig{ConfigVersions: store}, testEvaluator())
	server := httptest.NewServer(cpMux)
	defer server.Close()
	client := &cpConfigVersionClient{url: server.URL, client: server.Client()}
	mux := http.NewServeMux()
	registerCertsAdminRoutes(mux, admin, serverConfig{CPVersions: client}, testEvaluator(), nil)
	request := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(body)
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, httptest.NewRequest(method, path, bytes.NewReader(b)))
		return r
	}
	if r := request("PUT", "/admin/certs/node", certVersionSnapshot{CertPEM: c, KeyPEM: k}); r.Code != 200 {
		t.Fatalf("replace status %d", r.Code)
	}
	v, ok, err := client.Get(t.Context(), configversion.ResourceCertificate, "node", 1)
	if err != nil || !ok {
		t.Fatal("missing first version")
	}
	var snap certVersionSnapshot
	json.Unmarshal(v.Payload, &snap)
	if snap.CertPEM != oldCert || snap.KeyPEM != oldKey {
		t.Fatal("first version is not the original pair")
	}
	listed := request("GET", "/admin/certs/node/versions", nil)
	if bytes.Contains(listed.Body.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("private key returned by history")
	}
	if r := request("POST", "/admin/certs/node/rollback", map[string]int{"version_no": 1}); r.Code != 200 {
		t.Fatalf("rollback status %d", r.Code)
	}
	got, _ := os.ReadFile(cp)
	if string(got) != oldCert {
		t.Fatal("old certificate not restored")
	}
	got, _ = os.ReadFile(kp)
	if string(got) != oldKey {
		t.Fatal("old key not restored")
	}
	if _, err := certreload.NewReloadableCert(cp, kp); err != nil {
		t.Fatal(err)
	}
	// A failed history write must stop the change before touching current material.
	server.Close()
	r := request("PUT", "/admin/certs/node", certVersionSnapshot{CertPEM: c, KeyPEM: k})
	if r.Code != 503 {
		t.Fatalf("history unavailable status %d", r.Code)
	}
	got, _ = os.ReadFile(cp)
	if string(got) != oldCert {
		t.Fatal("history failure changed certificate")
	}
}

func TestCertificateCommitFailureRestoresBothFiles(t *testing.T) {
	for _, tc := range []struct {
		name         string
		failAt       int
		afterReplace bool
	}{
		{"second rename refused", 2, false},
		{"first flush unconfirmed", 1, true},
		{"second flush unconfirmed", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp, kp, oldCert, oldKey := rotationRecoveryFiles(t)
			c, k := rotationRecoveryPair(t, 2)
			calls := 0
			replace := func(from, to string) error {
				calls++
				if calls == tc.failAt {
					if !tc.afterReplace {
						return os.ErrPermission
					}
					if err := durablefile.Replace(from, to); err != nil {
						return err
					}
					return errors.Join(durablefile.ErrReplacedNotFlushed, os.ErrPermission)
				}
				return durablefile.Replace(from, to)
			}
			if err := saveNamedCertPairWithReplace(cp, kp, []byte(c), []byte(k), replace); err == nil {
				t.Fatal("injected failure reported success")
			}
			for p, want := range map[string]string{cp: oldCert, kp: oldKey} {
				got, err := os.ReadFile(p)
				if err != nil || string(got) != want {
					t.Fatal("previous pair was not restored")
				}
			}
			if _, err := tls.LoadX509KeyPair(cp, kp); err != nil {
				t.Fatal(err)
			}
		})
	}
}
