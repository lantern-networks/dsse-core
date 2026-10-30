package deploymentcrl

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKeylessReplicaSurvivesSourceOutageAndRejectsRollback(t *testing.T) {
	var source http.Handler
	available := true
	serveOldIssuer := false
	oldIssuerID := ""
	var oldIssuerDER []byte
	sourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if serveOldIssuer && strings.Contains(r.URL.Path, "/"+oldIssuerID+".crl") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(oldIssuerDER)
			return
		}
		source.ServeHTTP(w, r)
	}))
	defer sourceServer.Close()
	f := makeFixtureAt(t, sourceServer.URL)
	issuers := []*x509.Certificate{f.root, f.issuer}
	authorityDir := filepath.Join(t.TempDir(), "authority")
	sourceDir := filepath.Join(t.TempDir(), "source")
	replicaDir := filepath.Join(t.TempDir(), "replica")
	signers := []Issuer{{f.root, f.rootKey}, {f.issuer, f.issuerKey}}
	if err := Refresh(authorityDir, sourceDir, f.root, signers, nil, f.now); err != nil {
		t.Fatal(err)
	}
	var err error
	source, err = Handler(sourceDir, f.root, issuers, []string{sourceServer.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := Replicate(context.Background(), sourceServer.URL, replicaDir, f.root, issuers, sourceServer.Client(), f.now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := ReplicaReady(replicaDir, f.root, issuers, f.now, time.Hour); err != nil {
		t.Fatal(err)
	}
	replicaOrigin := "http://replica.example.test"
	replica, err := Handler(replicaDir, f.root, issuers, []string{replicaOrigin})
	if err != nil {
		t.Fatal(err)
	}
	path, err := DistributionPoints([]string{replicaOrigin}, f.root, f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	request := func() int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path[0], nil)
		rr := httptest.NewRecorder()
		replica.ServeHTTP(rr, req)
		return rr.Code
	}
	available = false
	if got := request(); got != http.StatusOK {
		t.Fatalf("replica stopped serving when source failed: %d", got)
	}
	if err := ReplicaReady(replicaDir, f.root, issuers, f.now.Add(25*time.Hour), 0); err == nil {
		t.Fatal("expired replica was treated as ready")
	}

	oldIssuerDER, err = os.ReadFile(filepath.Join(sourceDir, Fingerprint(f.issuer)+".crl"))
	if err != nil {
		t.Fatal(err)
	}
	oldIssuerID = Fingerprint(f.issuer)
	if err := Refresh(authorityDir, sourceDir, f.root, signers, []Revocation{{f.issuer, f.leaf, 1}}, f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	available = true
	if err := Replicate(context.Background(), sourceServer.URL, replicaDir, f.root, issuers, sourceServer.Client(), f.now.Add(time.Minute), time.Hour); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(filepath.Join(replicaDir, Fingerprint(f.issuer)+".crl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStatus([]*x509.Certificate{f.leaf, f.issuer, f.root}, map[string][]byte{
		Fingerprint(f.root):   mustReadReplica(t, replicaDir, f.root),
		Fingerprint(f.issuer): current,
	}, f.now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("replicated revocation was not enforced: %v", err)
	}
	serveOldIssuer = true
	if err := Replicate(context.Background(), sourceServer.URL, replicaDir, f.root, issuers, sourceServer.Client(), f.now.Add(2*time.Minute), time.Hour); err == nil {
		t.Fatal("replica accepted CRL rollback")
	}
	after, err := os.ReadFile(filepath.Join(replicaDir, Fingerprint(f.issuer)+".crl"))
	if err != nil || string(after) != string(current) {
		t.Fatal("failed rollback changed published CRL")
	}
	if got := request(); got != http.StatusOK {
		t.Fatalf("rollback failure took down valid replica: %d", got)
	}
}

func mustReadReplica(t *testing.T, dir string, issuer *x509.Certificate) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, Fingerprint(issuer)+".crl"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReplicaRejectsPartialSourceAndIncompletePublication(t *testing.T) {
	var source http.Handler
	failIssuer := false
	issuerID := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failIssuer && strings.HasSuffix(r.URL.Path, "/"+issuerID+".crl") {
			http.Redirect(w, r, "/other", http.StatusFound)
			return
		}
		source.ServeHTTP(w, r)
	}))
	defer server.Close()
	f := makeFixtureAt(t, server.URL)
	issuerID = Fingerprint(f.issuer)
	issuers := []*x509.Certificate{f.root, f.issuer}
	authorityDir, sourceDir, replicaDir := filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "source"), filepath.Join(t.TempDir(), "replica")
	if err := Replicate(context.Background(), "http://unplanned.example.test", replicaDir, f.root, issuers, server.Client(), f.now, time.Hour); err == nil {
		t.Fatal("source origin absent from signed issuer CDP was accepted")
	}
	signers := []Issuer{{f.root, f.rootKey}, {f.issuer, f.issuerKey}}
	if err := Refresh(authorityDir, sourceDir, f.root, signers, nil, f.now); err != nil {
		t.Fatal(err)
	}
	var err error
	source, err = Handler(sourceDir, f.root, issuers, []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := Replicate(context.Background(), server.URL, replicaDir, f.root, issuers, server.Client(), f.now, time.Hour); err != nil {
		t.Fatal(err)
	}
	priorRoot := mustReadReplica(t, replicaDir, f.root)
	if err := Refresh(authorityDir, sourceDir, f.root, signers, nil, f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	failIssuer = true
	if err := Replicate(context.Background(), server.URL, replicaDir, f.root, issuers, server.Client(), f.now.Add(time.Minute), time.Hour); err == nil {
		t.Fatal("redirecting source accepted")
	}
	if current := mustReadReplica(t, replicaDir, f.root); string(current) != string(priorRoot) {
		t.Fatal("partial source failure published one issuer ahead of another")
	}
	if err := os.WriteFile(filepath.Join(replicaDir, publicationMarker), []byte("updating"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ReplicaReady(replicaDir, f.root, issuers, f.now, time.Hour); err == nil {
		t.Fatal("interrupted publication was considered ready")
	}
}
