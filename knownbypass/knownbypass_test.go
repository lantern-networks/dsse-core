package knownbypass

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCatalogMetadataAndVersion(t *testing.T) {
	cat := Catalog()
	if cat.Version != CatalogVersion || len(cat.Entries) == 0 {
		t.Fatalf("catalog version/entries: %+v", cat.Version)
	}
	ids := map[string]bool{}
	for _, e := range cat.Entries {
		if e.ID == "" || e.Vendor == "" || e.Category == "" || e.Risk == "" {
			t.Fatalf("catalog entry missing metadata: %+v", e)
		}
		if ids[e.ID] {
			t.Fatalf("duplicate catalog entry id %q", e.ID)
		}
		ids[e.ID] = true
		switch e.Risk {
		case "low", "medium", "high":
		default:
			t.Fatalf("entry %q has invalid risk %q", e.ID, e.Risk)
		}
	}
	if _, ok := EntryByID("apple_push"); !ok {
		t.Fatal("EntryByID should find a known entry")
	}
	if _, ok := EntryByID("does_not_exist"); ok {
		t.Fatal("EntryByID should miss an unknown entry")
	}
}

func TestEffectiveBypassHostsHonorsOverrides(t *testing.T) {
	base := EffectiveBypassHosts(nil)
	// Force-inspecting an entry drops exactly that entry's patterns from the bypass set.
	withOverride := EffectiveBypassHosts([]Override{{EntryID: "apple_push", Mode: OverrideForceInspect}})
	if len(withOverride) >= len(base) {
		t.Fatalf("force_inspect override must shrink the bypass set: base=%d overridden=%d", len(base), len(withOverride))
	}
	for _, h := range withOverride {
		if h == "*.push.apple.com" {
			t.Fatalf("force-inspected entry's pattern %q must not be in the bypass set", h)
		}
	}
	// "disabled" behaves the same for the bypass set.
	disabled := EffectiveBypassHosts([]Override{{EntryID: "windows_update", Mode: OverrideDisabled}})
	for _, h := range disabled {
		if strings.Contains(h, "windowsupdate.com") {
			t.Fatalf("disabled entry %q must not be bypassed", h)
		}
	}
}

func TestOverrideStoreSetClearListAndDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overrides.json")
	s := NewOverrideStore()
	if err := s.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := s.Set("acme", Override{EntryID: "apple_account_id", Mode: OverrideForceInspect, Reason: "tenant wants to inspect"}, now); err != nil {
		t.Fatal(err)
	}
	// Reject unknown entry / invalid mode (the override set cannot drift from the catalog).
	if _, err := s.Set("acme", Override{EntryID: "nope", Mode: OverrideForceInspect}, now); err == nil {
		t.Fatal("unknown entry must be rejected")
	}
	if _, err := s.Set("acme", Override{EntryID: "apple_account_id", Mode: "bogus"}, now); err == nil {
		t.Fatal("invalid mode must be rejected")
	}
	if got := s.List("acme"); len(got) != 1 || got[0].EntryID != "apple_account_id" {
		t.Fatalf("list: %+v", got)
	}
	// Effective hosts for the tenant exclude the force-inspected entry.
	for _, h := range s.EffectiveBypassHosts("acme") {
		if h == "gsa.apple.com" {
			t.Fatal("force-inspected entry must be excluded from the tenant's effective bypass")
		}
	}
	// Durability: a fresh store loading the same path sees the override.
	s2 := NewOverrideStore()
	if err := s2.SetStatePath(path); err != nil {
		t.Fatal(err)
	}
	if got := s2.List("acme"); len(got) != 1 {
		t.Fatalf("override must survive restart: %+v", got)
	}
	// Clear restores the default.
	if !s.Clear("acme", "apple_account_id") {
		t.Fatal("clear should report an existing override")
	}
	if len(s.List("acme")) != 0 {
		t.Fatal("override should be gone after clear")
	}
}

func TestDefaultBypassHostsCuratedAndSafe(t *testing.T) {
	hosts := DefaultBypassHosts()
	if len(hosts) == 0 {
		t.Fatal("default bypass list must not be empty")
	}
	set := map[string]bool{}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" || h == "*" {
			t.Fatalf("bypass pattern must be specific, got %q (a %q would bypass everything)", h, "*")
		}
		if set[h] {
			t.Fatalf("duplicate bypass pattern %q", h)
		}
		set[h] = true
	}
	// Must include the iCloud Private Relay ingress seen failing in the field, Apple push, and the Gatekeeper
	// ticket-delivery host — the last one measured breaking `stapler` on a Mac steered by this product, where
	// notarization SUCCEEDS and only the staple fails, so nothing announces it.
	for _, want := range []string{"mask.icloud.com", "*.push.apple.com", "*.apple-cloudkit.com"} {
		if !set[want] {
			t.Fatalf("expected %q in the default bypass list", want)
		}
	}
	// Must NOT bypass tenant-restriction interception targets (Google Workspace / Microsoft 365 auth).
	for _, banned := range hosts {
		l := strings.ToLower(banned)
		if strings.Contains(l, "login.microsoftonline") || strings.Contains(l, "accounts.google") || l == "*.google.com" {
			t.Fatalf("default bypass must not include a tenant-restriction interception target: %q", banned)
		}
	}
}
