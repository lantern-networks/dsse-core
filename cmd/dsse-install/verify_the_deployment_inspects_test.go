package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// interceptionRootsServer answers /admin/interception-roots with one PEM (or nothing).
func interceptionRootsServer(t *testing.T, rootPEM string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"default_root_pem": rootPEM})
	}))
	t.Cleanup(s.Close)
	return s
}

func deploymentWithTiers(t *testing.T) (string, *deploymentAuthorities) {
	t.Helper()
	dir := t.TempDir()
	a, err := mint("Acme", time.Now(), 10)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := writeAuthorities(dir, a); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deployment-anchor.pem"), certPEM(a.RootCert), 0o644); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	return dir, a
}

func insecureClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

// ★★★ A FLEET WHERE EACH NODE INVENTED ITS OWN ROOT LOOKS PERFECTLY HEALTHY FROM ANY SINGLE NODE. The engine
// mints its own authority when it finds no material, so a node that was missed signs under a root no device
// has heard of — and the only way to see it is to ask every node and compare.
func TestASplitInterceptionAuthorityIsRefused(t *testing.T) {
	dir, a := deploymentWithTiers(t)
	other, err := mint("Acme", time.Now(), 10) // a second deployment's authority
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	good := interceptionRootsServer(t, string(certPEM(a.InterceptCA)))
	odd := interceptionRootsServer(t, string(certPEM(other.InterceptCA)))

	results := verifyTheDeploymentInspects(insecureClient(), dir, []string{good.URL, odd.URL}, "")
	if !anyFailedContaining(results, "different interception authorities") {
		t.Fatalf("a split fleet must be refused: %v", describeResults(results))
	}
}

// An Edge that reports no authority inspects nothing, and a deployment where that is true of SOME nodes
// decrypts a device or not depending on where its flows land.
func TestAnEdgeWithNoInterceptionAuthorityIsRefused(t *testing.T) {
	dir, a := deploymentWithTiers(t)
	good := interceptionRootsServer(t, string(certPEM(a.InterceptCA)))
	none := interceptionRootsServer(t, "")

	results := verifyTheDeploymentInspects(insecureClient(), dir, []string{good.URL, none.URL}, "")
	if !anyFailedContaining(results, "inspect NOTHING") {
		t.Fatalf("a half-inspecting fleet must be refused: %v", describeResults(results))
	}

	// And a deployment where NO node has one says that plainly rather than as a split.
	results = verifyTheDeploymentInspects(insecureClient(), dir, []string{none.URL}, "")
	if !anyFailedContaining(results, "nothing is being decrypted anywhere") {
		t.Fatalf("a deployment that inspects nothing must say so: %v", describeResults(results))
	}
}

// ★ AND IT HAS TO BE THIS DEPLOYMENT'S. A device trusts the anchor and nothing else, so an authority that
// does not chain to it is one every device would be refused by its own Edge.
func TestAnInterceptionAuthorityFromAnotherDeploymentIsRefused(t *testing.T) {
	dir, _ := deploymentWithTiers(t)
	other, err := mint("Acme", time.Now(), 10)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	all := interceptionRootsServer(t, string(certPEM(other.InterceptCA)))

	results := verifyTheDeploymentInspects(insecureClient(), dir, []string{all.URL}, "")
	if !anyFailedContaining(results, "does not chain to this deployment's anchor") {
		t.Fatalf("a foreign authority must be refused: %v", describeResults(results))
	}

	// The control: this deployment's own authority passes both assertions.
	dirB, b := deploymentWithTiers(t)
	mine := interceptionRootsServer(t, string(certPEM(b.InterceptCA)))
	results = verifyTheDeploymentInspects(insecureClient(), dirB, []string{mine.URL}, "")
	for _, r := range results {
		if !r.ok {
			t.Fatalf("this deployment's own authority was refused: %s — %s", r.name, r.note)
		}
	}
	if len(results) != 2 {
		t.Fatalf("both questions must be answered, got %d: %v", len(results), describeResults(results))
	}
	// Sanity: the fixture really does chain, so the control is not passing by accident.
	pool := x509.NewCertPool()
	pool.AddCert(b.RootCert)
	if _, err := b.InterceptCA.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("fixture: %v", err)
	}
}

func anyFailedContaining(results []verifyResult, needle string) bool {
	for _, r := range results {
		if !r.ok && strings.Contains(r.note, needle) {
			return true
		}
	}
	return false
}

func describeResults(results []verifyResult) []string {
	out := []string{}
	for _, r := range results {
		out = append(out, r.name+": "+r.note)
	}
	return out
}
