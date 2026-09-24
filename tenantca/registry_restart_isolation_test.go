package tenantca

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Runtime saves use inline PEM. Restart must enforce the same ownership rule as
// registration and file-based certificates; input order cannot reassign a CA.
func TestRegistryRestartRejectsAmbiguousInlineOwnership(t *testing.T) {
	cert, _, pem := mkCA(t, "restart-owner")
	for _, firstFile := range []bool{false, true} {
		name := "inline_then_inline"
		if firstFile {
			name = "file_then_inline"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			caPath := filepath.Join(dir, "ca.pem")
			if err := os.WriteFile(caPath, pem, 0600); err != nil {
				t.Fatal(err)
			}
			first := TenantCAEntry{TenantID: "original", CAPEM: string(pem)}
			if firstFile {
				first.CAPEM = ""
				first.CAFile = caPath
			}
			raw, err := json.Marshal(TenantCARegistryFile{Tenants: []TenantCAEntry{first, {TenantID: "other", CAPEM: string(pem)}}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "registry.json")
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			reg, err := LoadTenantCARegistry(path)
			if err == nil {
				owner, _ := reg.TenantForVerifiedChains([][]*x509.Certificate{{cert}})
				t.Fatalf("restart accepted ambiguous CA ownership and resolves original certificate as %q", owner)
			}
			if reg != nil || !strings.Contains(err.Error(), "isolation violation") {
				t.Fatalf("unexpected result: registry=%v error=%v", reg, err)
			}
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(saved) != string(raw) {
				t.Fatal("rejected registry was modified")
			}
		})
	}
}

func TestRegistryRestartPreservesDistinctTenantOwnership(t *testing.T) {
	a, _, ap := mkCA(t, "owner-a")
	b, _, bp := mkCA(t, "owner-b")
	r := NewTenantCARegistry()
	for name, p := range map[string][]byte{"a": ap, "b": bp} {
		if _, err := r.Register(name, p); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := r.Save(path); err != nil {
		t.Fatal(err)
	}
	fresh, err := LoadTenantCARegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*x509.Certificate{"a": a, "b": b} {
		if owner, ok := fresh.TenantForVerifiedChains([][]*x509.Certificate{{c}}); !ok || owner != name {
			t.Fatalf("%s resolved as %q (%v)", name, owner, ok)
		}
	}
}
