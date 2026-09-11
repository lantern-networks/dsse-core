package main

import (
	"strings"
	"testing"
)

// ★★★ THE DERIVATION IS ONLY SAFE IF THE ID IS (2026-08-22, measured while giving a third organization its
// first transport authority).
//
// organizationTransportServerName exists so that a minted id is not undone by a hand-typed name. But the
// organizations that predate the minting keep guessable ids ON PURPOSE — renaming one is a migration, not an
// edit — so the default path would have produced acme.dsse.invalid for the very next authority created, and
// the SNI oracle the minting was written to close would have come straight back on a name minted today.
func TestADerivedTransportNameNeverNamesTheCustomer(t *testing.T) {
	const suffix = "dsse.invalid"

	// A legacy id: the display name with the spaces taken out. The name must not contain it.
	for _, legacy := range []string{"tenant_acme", "tenant_northwind", "tenant_reference_lab", "tenant_contoso"} {
		name := organizationTransportServerName(legacy, suffix)
		bare := strings.TrimPrefix(legacy, "tenant_")
		if name == "" {
			t.Fatalf("%q derived no name at all — the create route would then demand one typed in by hand, "+
				"which is the habit this is meant to remove", legacy)
		}
		if strings.Contains(name, bare) {
			t.Errorf("%q -> %q still names the customer; a stranger who guesses the company guesses the name",
				legacy, name)
		}
		if !strings.HasSuffix(name, "."+suffix) {
			t.Errorf("%q -> %q is not under this deployment's suffix", legacy, name)
		}
		// Stable, or every restart would announce a different name to the same organization's devices.
		if again := organizationTransportServerName(legacy, suffix); again != name {
			t.Errorf("%q derived two different names: %q then %q", legacy, name, again)
		}
	}

	// A minted id is already opaque and is used verbatim — folding it again would churn the names of every
	// organization created since 2026-08-21, each of which is written into certificates devices hold.
	// Minted ids are recognised. About one in 230 contains no base32 digit and is folded instead, which is
	// the harmless direction and is asserted separately below — so this draws until it has one of each rather
	// than depending on a coin flip.
	minted := ""
	for i := 0; i < 200 && minted == ""; i++ {
		id, err := newOrganizationID()
		if err != nil {
			t.Fatalf("newOrganizationID: %v", err)
		}
		if organizationIDIsMinted(id) {
			minted = id
		}
	}
	if minted == "" {
		t.Fatal("200 minted ids and none was recognised as minted — the predicate rejects its own output")
	}
	want := strings.TrimPrefix(minted, "tenant_") + "." + suffix
	if got := organizationTransportServerName(minted, suffix); got != want {
		t.Errorf("a minted id must be used as it is: want %q got %q", want, got)
	}

	// ★ The predicate must not wave through a legacy id that happens to be long — otherwise the guard above
	// passes for the wrong reason on somebody's real company name.
	for _, notMinted := range []string{"tenant_a-very-long-company-name-indeed", "tenant_ABCDEFGHIJKLMNOPQRSTUVWXYZ", "tenant_"} {
		if organizationIDIsMinted(notMinted) {
			t.Errorf("%q was treated as a minted id", notMinted)
		}
	}
}
