package main

import (
	"strings"
	"testing"
)

// ★★★ THE DEPLOYMENT SIGNED UNDER ONE ROOT AND TOLD ITS DEVICES TO LOOK FOR ANOTHER (2026-08-30, measured on
// a deployment stood up from nothing this morning; reported by win-dev-1 from the device side).
//
//	signing   769131f4…  CN=Lantern DSSE Interception Root (tenant_zkn2u436c5g53gfwzdcbddrfqy)
//	announced 83fe37b9…  O=Hikari Networks, CN=Hikari Networks Root CA
//
// An organization comes to sign under its own root in TWO ways: an offline intermediate imported from material
// it signed itself, and a root minted here through POST /admin/interception-roots/{tenant}. Every function
// that asked "does this organization have an issuer of its own" enumerated the first only — so the second
// signed the organization's traffic while its devices were told to look for the deployment's root, reported
// interception_root_trust wanted=1 found=0, and never looked for the certificate actually signing them.
//
// Worse, the check written to prove those two cannot drift enumerated the first only as well. It reported
// nothing throughout — a green light with a hole in it, which is what the signal it replaced also did.
func TestTheMismatchCheckSeesAMintedRoot(t *testing.T) {
	// The announcement and the check must read a minted root through the same helper, so they cannot answer
	// differently about the same certificate.
	for _, file := range []string{
		"trust_bundle_per_tenant.go",
		"interception_announced_vs_signing.go",
	} {
		body := readFileForTest(t, file)
		if !strings.Contains(body, "ListTenantInterceptionRoots()") {
			t.Errorf("%s still enumerates only offline intermediates, so an organization whose root was minted "+
				"on this node is invisible to it", file)
		}
	}
}

// The mismatch itself, stated where it can be shown to fail. A check that cannot be shown failing is not
// evidence of anything — the comment in interception_announced_vs_signing.go says so about its predecessor.
func TestAnAnnouncementThatDoesNotCoverTheSigningRootIsAMismatch(t *testing.T) {
	lines := interceptionAnnouncementMismatchLines([]interceptionAnnouncement{{
		Tenant:         "tenant_zkn2u436c5g53gfwzdcbddrfqy",
		IntermediateCN: "(minted per-tenant root, no intermediate)",
		RootCommonName: "Lantern DSSE Interception Root (tenant_zkn2u436c5g53gfwzdcbddrfqy)",
		SigningSHA256:  "769131f47d7475451643fd93f248704ed602af490aad5fb4715e13bbf295fd26",
		Announced:      []string{"83fe37b98013a975feb9b32f8cfddf435e0090b46129056bb89f2252d4d2ad06"},
	}})
	if len(lines) == 0 {
		t.Fatal("an organization signed under one root and told its devices to look for another, and the check " +
			"that exists to catch exactly that said nothing")
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "769131f4") || !strings.Contains(joined, "83fe37b9") {
		t.Fatalf("the mismatch does not name both certificates, so an operator cannot act on it:\n%s", joined)
	}
}

func TestAnAnnouncementThatCoversTheSigningRootIsNot(t *testing.T) {
	if lines := interceptionAnnouncementMismatchLines([]interceptionAnnouncement{{
		Tenant:        "tenant_zkn2u436c5g53gfwzdcbddrfqy",
		SigningSHA256: "769131f47d7475451643fd93f248704ed602af490aad5fb4715e13bbf295fd26",
		Announced: []string{
			"769131f47d7475451643fd93f248704ed602af490aad5fb4715e13bbf295fd26",
			"83fe37b98013a975feb9b32f8cfddf435e0090b46129056bb89f2252d4d2ad06",
		},
	}}); len(lines) != 0 {
		t.Fatalf("a healthy overlap — the signing root plus one being moved off — was reported as a mismatch:\n%s",
			strings.Join(lines, "\n"))
	}
}
