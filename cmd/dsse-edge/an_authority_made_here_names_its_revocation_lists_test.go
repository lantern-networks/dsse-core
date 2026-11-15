package main

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/inspectioncrl"
)

// An interception authority the deployment makes for an organization keeps no root key. On a deployment that
// publishes revocation lists, the root signs one sealed list before its key is dropped, and the issuing
// certificate names where the lists are published — so a client that requires a revocation answer has one for
// every certificate in the chain.
func TestAnAuthorityMadeHereNamesItsRevocationListsAndSealsTheRootsList(t *testing.T) {
	const tenant = "tenant_made_here"
	origins := []string{"http://crl.example.test"}
	now := time.Now()
	rootPEM, issuingPEM, keyPEM, sealed, err := mintTenantInterceptionAuthorityPublishingAt(tenant, "Example Customer", now, origins)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := parseFirstCertificatePEM([]byte(rootPEM))
	issuing, _ := parseFirstCertificatePEM([]byte(issuingPEM))
	want, _ := inspectioncrl.URLs(origins, tenant, root)
	if len(issuing.CRLDistributionPoints) != 1 || issuing.CRLDistributionPoints[0] != want[0] {
		t.Fatalf("the issuing certificate names %v, want %v", issuing.CRLDistributionPoints, want)
	}
	list, err := x509.ParseRevocationList(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !list.NextUpdate.Equal(issuing.NotAfter) || len(list.RevokedCertificateEntries) != 0 {
		t.Fatalf("the sealed list ends %s (issuing certificate ends %s) with %d entries", list.NextUpdate, issuing.NotAfter, len(list.RevokedCertificateEntries))
	}
	// The ordinary rule still refuses a list this long: only a row that records the key was not kept accepts it.
	if _, err := inspectioncrl.ParseAndValidate(sealed, root, now); err == nil {
		t.Fatal("a two-year list passed the ordinary validity bound; the test would prove nothing about the exception")
	}

	authority := &tenantInterceptionAuthority{issuers: map[string]*storedTenantInterceptionIssuer{}, now: time.Now}
	if _, err := authority.Import(tenant, rootPEM, issuingPEM, keyPEM, sealed); err == nil {
		t.Fatal("an organization that brings its own PKI was allowed a list valid for years")
	}
	row, err := authority.ImportMadeHere(tenant, rootPEM, issuingPEM, keyPEM, sealed)
	if err != nil {
		t.Fatalf("the authority this deployment made does not pass its own import: %v", err)
	}
	if !row.RootKeyNotKept || row.CRLBaseURL != origins[0] {
		t.Fatalf("stored as root_key_not_kept=%t base=%q", row.RootKeyNotKept, row.CRLBaseURL)
	}
	// Both lists a client will ask for are served: the root's sealed one and the issuing authority's.
	for name, fp := range map[string]string{"root": inspectioncrl.Fingerprint(root), "issuing": inspectioncrl.Fingerprint(issuing)} {
		status, err := authority.crlStatus(context.Background(), tenant, fp)
		if err != nil || len(status.DER) == 0 {
			t.Fatalf("the %s list is not served: %v", name, err)
		}
	}
	// Nothing can sign for this root again, and an attempt is told why.
	if err := authority.updateRootCRL(context.Background(), tenant, sealed); err == nil {
		t.Fatal("a new root list was accepted for a root whose key does not exist")
	}

	// A deployment that publishes no lists makes an authority exactly as before.
	_, plainIssuingPEM, _, none, err := mintTenantInterceptionAuthorityPublishingAt(tenant, "Example Customer", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := parseFirstCertificatePEM([]byte(plainIssuingPEM))
	if len(none) != 0 || len(plain.CRLDistributionPoints) != 0 {
		t.Fatal("an authority names revocation lists on a deployment that publishes none")
	}
}

func TestASealedListThatRevokesIsRefused(t *testing.T) {
	const tenant = "tenant_made_here"
	now := time.Now()
	rootPEM, issuingPEM, _, _, err := mintTenantInterceptionAuthorityPublishingAt(tenant, "Example Customer", now, []string{"http://crl.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	_ = rootPEM
	issuing, _ := parseFirstCertificatePEM([]byte(issuingPEM))
	if _, err := inspectioncrl.SignSealed(issuing, nil, now, now.Add(time.Hour)); err == nil {
		t.Fatal("a sealed list was signed without a key")
	}
}
