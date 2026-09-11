package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"

	tenantca "github.com/lantern-networks/dsse-core/tenantca"
)

func TestLoadEnrolledInventory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "inv.json")
	if err := os.WriteFile(p, []byte(`{"enrolled_identities":["Mac-Dev-1"," win-dev-1 ","conn-lab-1",""]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := loadEnrolledInventory(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// lowercased + trimmed; empty dropped
	for _, want := range []string{"mac-dev-1", "win-dev-1", "conn-lab-1"} {
		if _, ok := set[want]; !ok {
			t.Errorf("expected %q in inventory, set=%v", want, set)
		}
	}
	if len(set) != 3 {
		t.Errorf("expected 3 identities, got %d (%v)", len(set), set)
	}
	if _, err := loadEnrolledInventory(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected error for missing inventory file (fail-closed)")
	}
}

// The store's shape (enrolled_inventory_state.v1 `entries` map) must read, and an EMPTY managed store must be
// a recognized empty allowlist — not an error — so bring-up before the first enrolment is not a fatal.
func TestLoadEnrolledInventoryStoreShape(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "store.json")
	body := `{"schema_version":"enrolled_inventory_state.v1","entries":{` +
		`"mac-dev-1":{"identity":"mac-dev-1","enabled":true},` +
		`"old-dev":{"identity":"old-dev","enabled":false}},"groups":{}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := loadEnrolledInventory(p)
	if err != nil {
		t.Fatalf("store shape: %v", err)
	}
	if _, ok := set["mac-dev-1"]; !ok {
		t.Errorf("enabled entry missing: %v", set)
	}
	if _, ok := set["old-dev"]; ok {
		t.Errorf("disabled entry must not be admitted: %v", set)
	}
	// An empty MANAGED store is a recognized, legitimately-empty allowlist — not a fatal at bring-up.
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte(`{"schema_version":"enrolled_inventory_state.v1","entries":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := loadEnrolledInventory(empty); err != nil || len(s) != 0 {
		t.Errorf("empty managed store must be (empty set, nil), got set=%v err=%v", s, err)
	}
}

// Format drift is the 2026-08-02 failure: a file that carries NEITHER recognized key parsed to zero identities
// not because nobody is enrolled but because its shape changed under the reader. That must be a LOUD error, not
// a silent empty allowlist that arms a deny-all against a fleet that is in fact enrolled.
func TestLoadEnrolledInventoryUnrecognizedShapeIsAnError(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"future_shape": `{"schema_version":"enrolled_inventory_state.v2","devices":{"mac-dev-1":{}}}`,
		"empty_object": `{}`,
	} {
		p := filepath.Join(dir, name+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if set, err := loadEnrolledInventory(p); err == nil {
			t.Errorf("%s: expected an error for an unrecognized shape, got set=%v (a silent deny-all)", name, set)
		}
	}
}

// admissionTLSConfig builds a lab (T) tls.Config with the enrolled-identity gate enabled.
func admissionTLSConfig(t *testing.T, enrolled ...string) *tls.Config {
	t.Helper()
	set := make(map[string]struct{}, len(enrolled))
	for _, e := range enrolled {
		set[e] = struct{}{}
	}
	cfg, err := buildSecureTransportTLSConfig(secureTransportConfig{
		ListenAddr:              "127.0.0.1:0",
		LabAutoCert:             true,
		LabMode:                 true,
		RequireEnrolledIdentity: true,
		EnrolledIdentities:      set,
	})
	if err != nil {
		t.Fatalf("buildSecureTransportTLSConfig: %v", err)
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("expected VerifyConnection admission gate to be set")
	}
	return cfg
}

func csWithCN(cn string) tls.ConnectionState {
	if cn == "__none__" {
		return tls.ConnectionState{}
	}
	return tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}}
}

// single-tenant Edge isolation: even when the registry trusts multiple tenants' CAs, an Edge bound
// to tenant_a must DENY a cross-tenant cert (tenant_b) at the handshake.
func TestTransportAdmissionTenantBinding(t *testing.T) {
	dir := t.TempDir()
	caA := makeTestCA(t, dir, "tenant-A-CA", 11)
	caB := makeTestCA(t, dir, "tenant-B-CA", 12)
	regPath := writeRegistry(t, dir, map[string]string{"tenant_a": caA.pemPath, "tenant_b": caB.pemPath})
	reg, err := tenantca.LoadTenantCARegistry(regPath)
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	cfg, err := buildSecureTransportTLSConfig(secureTransportConfig{
		ListenAddr: "127.0.0.1:0", LabAutoCert: true, LabMode: true,
		TenantCARegistry: reg, ExpectedTenantID: "tenant_a",
	})
	if err != nil {
		t.Fatalf("build tls cfg: %v", err)
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("expected tenant-binding VerifyConnection")
	}
	csFor := func(chains [][]*x509.Certificate) tls.ConnectionState {
		return tls.ConnectionState{PeerCertificates: []*x509.Certificate{chains[0][0]}, VerifiedChains: chains}
	}

	t.Run("own-tenant cert admitted", func(t *testing.T) {
		chains := leafSignedBy(t, caA, "dev-a", reg.Pool)
		if chains == nil {
			t.Fatal("A cert should verify")
		}
		if err := cfg.VerifyConnection(csFor(chains)); err != nil {
			t.Fatalf("tenant_a cert must be admitted on a tenant_a Edge: %v", err)
		}
	})
	t.Run("cross-tenant cert denied (isolation)", func(t *testing.T) {
		chains := leafSignedBy(t, caB, "dev-b", reg.Pool)
		if chains == nil {
			t.Fatal("B cert should verify against the pool (its CA is trusted)")
		}
		if err := cfg.VerifyConnection(csFor(chains)); err == nil {
			t.Fatal("ISOLATION VIOLATION: a tenant_b cert must be denied on a tenant_a Edge")
		}
	})
}

func TestTransportAdmissionGate(t *testing.T) {
	cfg := admissionTLSConfig(t, "mac-dev-1", "conn-lab-1")

	t.Run("enrolled identity admitted", func(t *testing.T) {
		if err := cfg.VerifyConnection(csWithCN("mac-dev-1")); err != nil {
			t.Fatalf("enrolled identity must be admitted, got %v", err)
		}
	})
	t.Run("enrolled identity case-insensitive", func(t *testing.T) {
		if err := cfg.VerifyConnection(csWithCN("MAC-DEV-1")); err != nil {
			t.Fatalf("admission should be case-insensitive, got %v", err)
		}
	})
	t.Run("unenrolled identity rejected", func(t *testing.T) {
		if err := cfg.VerifyConnection(csWithCN("rogue-9")); err == nil {
			t.Fatal("unenrolled identity must be rejected (not open to the world)")
		}
	})
	t.Run("no identity rejected", func(t *testing.T) {
		if err := cfg.VerifyConnection(csWithCN("")); err == nil {
			t.Fatal("cert without identity must be rejected")
		}
	})
	t.Run("no client cert rejected", func(t *testing.T) {
		if err := cfg.VerifyConnection(csWithCN("__none__")); err == nil {
			t.Fatal("missing client cert must be rejected")
		}
	})
	t.Run("empty inventory = deny all (fail-closed)", func(t *testing.T) {
		denyAll := admissionTLSConfig(t)
		if err := denyAll.VerifyConnection(csWithCN("mac-dev-1")); err == nil {
			t.Fatal("empty enrolled inventory must deny all")
		}
	})
}
