package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ★★★ EACH MACHINE GETS ITS OWN MEMBER MATERIAL, AND NOBODY ELSE'S (2026-08-31).
//
// The two paths are the same on every machine so that nothing has to vary per region, which means the bytes
// are what separates them. Getting that wrong ships the founding member's private key to every other machine
// — and the store is what decides which database is primary, so holding a member's key is holding a vote.
func TestEachRegionsMemberMaterialIsItsOwn(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	sa, err := mintStoreAuthority("Example", now, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStoreAuthority(dir, sa); err != nil {
		t.Fatal(err)
	}

	// ★ THE KEY DOES NOT TRAVEL. It is written where carry structurally refuses to walk.
	if _, err := os.Stat(filepath.Join(dir, authorityDirName, storeCAKeyFile)); err != nil {
		t.Fatalf("the store authority's key is not in the directory that does not travel: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, storeCAFile)); err != nil {
		t.Fatalf("the store authority's certificate is not where a member would mount it: %v", err)
	}

	tokyo := map[string]string{
		"DSSE_ETCD_A_NAME":           "dsse-store-tokyo-a",
		"DSSE_ETCD_A_PEER_ADVERTISE": "http://node-tokyo-a.example.test:12390",
	}
	osaka := map[string]string{
		"DSSE_ETCD_A_NAME":           "dsse-store-osaka",
		"DSSE_ETCD_A_PEER_ADVERTISE": "http://node-osaka.example.test:12390",
	}

	certA, keyA, err := storeMemberMaterialFor(dir, tokyo, now, 5)
	if err != nil {
		t.Fatal(err)
	}
	certB, keyB, err := storeMemberMaterialFor(dir, osaka, now, 5)
	if err != nil {
		t.Fatal(err)
	}
	if string(keyA) == string(keyB) {
		t.Fatal("two regions were issued the same private key, so every machine holds every member's vote")
	}

	// ★ THE NAME IN THE CERTIFICATE IS THE NAME PEERS DIAL. Derived from the same value that tells them where
	// to go, because two answers to that question is a cluster whose members reach each other and refuse
	// each other.
	for _, c := range []struct {
		pem  []byte
		san  string
		name string
	}{
		{certA, "node-tokyo-a.example.test", "dsse-store-tokyo-a"},
		{certB, "node-osaka.example.test", "dsse-store-osaka"},
	} {
		parsed, perr := firstCertificateIn(c.pem)
		if perr != nil {
			t.Fatal(perr)
		}
		found := false
		for _, n := range parsed.DNSNames {
			if n == c.san {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not valid for %s, which is the name its peers dial: %v", c.name, c.san, parsed.DNSNames)
		}
		if parsed.Subject.CommonName != c.name {
			t.Errorf("the certificate calls the member %q, the cluster calls it %q", parsed.Subject.CommonName, c.name)
		}
		// ★ BOTH HALVES. etcd peers dial each other, so every member is the caller half the time and the
		// answerer the other half; a certificate good for one of those makes a cluster that connects one way.
		server, client := false, false
		for _, u := range parsed.ExtKeyUsage {
			if u == x509.ExtKeyUsageServerAuth {
				server = true
			}
			if u == x509.ExtKeyUsageClientAuth {
				client = true
			}
		}
		if !server || !client {
			t.Errorf("%s is not both a server and a client certificate (server=%v client=%v)", c.name, server, client)
		}
	}
}

// ★★★ THE MATERIAL EXISTS EVEN WHERE IT IS NEVER PRESENTED (2026-08-31, changed from the opposite).
//
// This test used to require that a single-region deployment was issued nothing, which read well and was
// wrong: the compose file mounts these three paths on every machine, and Docker answers a mount of a path
// that is not there by creating an EMPTY DIRECTORY. A one-host deployment would have started with a
// directory where a certificate belongs, and nothing would have said so.
//
// So the material is always issued and TLS is what is conditional. It costs one certificate nobody presents.
func TestAOneHostDeploymentStillHasMaterialForItsMounts(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	sa, err := mintStoreAuthority("Example", now, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStoreAuthority(dir, sa); err != nil {
		t.Fatal(err)
	}
	cert, key, err := storeMemberMaterialFor(dir, nil, now, 5)
	if err != nil {
		t.Fatalf("a one-host deployment was refused material: %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("a one-host deployment was issued nothing, so its compose mounts would become empty directories")
	}
	parsed, perr := firstCertificateIn(cert)
	if perr != nil {
		t.Fatal(perr)
	}
	// ★ AND IT NAMES THE MEMBER ITS COMPOSE SERVICE IS CALLED, because on one host that is the name anything
	// reaching it would use.
	if parsed.Subject.CommonName != "dsse-store-a" {
		t.Errorf("the one-host member calls itself %q", parsed.Subject.CommonName)
	}
}

// ★ AND A DEPLOYMENT WITH NO STORE AUTHORITY AT ALL IS REFUSED, not quietly given nothing. One minted before
// the store had an authority cannot be handed a member certificate, and inventing one that verifies against
// nobody is worse than saying so.
func TestADeploymentWithoutAStoreAuthorityIsRefused(t *testing.T) {
	if _, _, err := storeMemberMaterialFor(t.TempDir(), nil, time.Now().UTC(), 5); err == nil {
		t.Fatal("a deployment with no store authority was issued a member certificate from nothing")
	}
}
