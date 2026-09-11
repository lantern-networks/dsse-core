//go:build windows

package configstore

import (
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/installprofile"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// TestRegistryBackend_RoundTrip exercises the real registry Backend under HKCU (no admin needed) so the
// production code path — CreateKey / Set / Get / Clear over the Windows registry — is verified on a real
// machine. Production uses HKLM (admin-only ACL); the logic is identical.
func TestRegistryBackend_RoundTrip(t *testing.T) {
	const testPath = `SOFTWARE\DSSE\_configstore_test`
	// clean any prior run, and clean up after.
	registry.DeleteKey(registry.CURRENT_USER, testPath)
	t.Cleanup(func() { registry.DeleteKey(registry.CURRENT_USER, testPath) })

	b, err := OpenRegistryBackend(registry.CURRENT_USER, testPath)
	if err != nil {
		t.Fatalf("open registry backend: %v", err)
	}

	// missing value reads as absent, no error.
	if v, ok, err := b.Get("nope"); err != nil || ok || v != "" {
		t.Fatalf("absent value: v=%q ok=%v err=%v", v, ok, err)
	}

	if err := b.Set(valEnvelope, `{"x":1}`); err != nil {
		t.Fatalf("set: %v", err)
	}
	if v, ok, err := b.Get(valEnvelope); err != nil || !ok || v != `{"x":1}` {
		t.Fatalf("get after set: v=%q ok=%v err=%v", v, ok, err)
	}

	// full Apply→Load round-trip through the registry backend.
	env, pub := signProfile(t, installprofile.InstallProfile{Version: 7, TenantID: "acme", TransportURL: "https://edge.acme:18543"})
	if _, err := Apply(b, env, pub, "bundled", "2026-07-21T00:00:00Z"); err != nil {
		t.Fatalf("apply via registry: %v", err)
	}
	got, meta, err := Load(b, pub)
	if err != nil || !meta.Verified || got.TenantID != "acme" {
		t.Fatalf("registry round-trip: got=%+v meta=%+v err=%v", got, meta, err)
	}

	if err := b.Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, ok, _ := b.Get(valEnvelope); ok {
		t.Fatalf("Clear left the envelope value behind")
	}
}

// TestHardenKeyACL sets the hardened DACL on a throwaway HKCU key (settable without admin — the current user
// owns their own hive) and reads it back to confirm it is PROTECTED and carries the SYSTEM/Admin-full,
// Users-read ACEs. Production applies the identical DACL to the HKLM key as SYSTEM at install time.
func TestHardenKeyACL(t *testing.T) {
	const testPath = `SOFTWARE\DSSE\_configstore_acl_test`
	registry.DeleteKey(registry.CURRENT_USER, testPath)
	t.Cleanup(func() { registry.DeleteKey(registry.CURRENT_USER, testPath) })

	if _, err := OpenRegistryBackend(registry.CURRENT_USER, testPath); err != nil {
		t.Fatalf("create key: %v", err)
	}
	if err := HardenKeyACL(registry.CURRENT_USER, testPath); err != nil {
		t.Fatalf("harden: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(`CURRENT_USER\`+testPath, windows.SE_REGISTRY_KEY, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read back security info: %v", err)
	}
	got := sd.String() // SDDL, e.g. "D:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)"
	for _, want := range []string{"D:P", "(A;;KA;;;SY)", "(A;;KA;;;BA)", "(A;;KR;;;BU)"} {
		if !strings.Contains(got, want) {
			t.Fatalf("hardened DACL %q missing %q", got, want)
		}
	}
}
