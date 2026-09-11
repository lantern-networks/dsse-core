package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enroll"
)

// A connector proves itself with its Site's bootstrap secret, and the organization it is issued under comes
// from the Site that secret belongs to — never from the request. These tests hold that line from the OUTSIDE:
// they call the eligibility exactly as the enrol endpoint does, so a change that stops consulting it fails here.

func connectorTestSiteStore(t *testing.T) adminSiteStore {
	t.Helper()
	// A durable store in the test's own directory. Not an in-memory stand-in: the store's Get is what decides
	// the answer, and a fake one would be measuring the fake.
	return newDurableAdminSiteStore(t.TempDir() + "/sites.json")
}

func seedSiteWithSecret(t *testing.T, store adminSiteStore, tenant, site, secret string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := store.Upsert(context.Background(), adminSiteModel{
		TenantID: tenant, SiteID: site, Name: site,
		BootstrapSecretHash: connectorRuntimeSecretHash(secret),
	}, now); err != nil {
		t.Fatalf("seed site: %v", err)
	}
}

func connectorReq(deviceID, tenant, site, secret string) enroll.Request {
	return enroll.Request{
		DeviceID:    deviceID,
		Tenant:      tenant,
		Eligibility: enroll.Eligibility{Mode: connectorEligibilityMode, Token: secret, Site: site},
		CSRPEM:      "",
	}
}

func TestAConnectorIsIssuedUnderTheOrganizationItsSiteBelongsTo(t *testing.T) {
	store := connectorTestSiteStore(t)
	seedSiteWithSecret(t, store, "tenant_a", "site-1", "s3cret-for-site-1")

	tenant, ok := connectorEnrolmentEligibility(context.Background(), store, "tenant_a",
		connectorReq("conn-1", "tenant_a", "site-1", "s3cret-for-site-1"), nil)
	if !ok {
		t.Fatal("a connector presenting its own Site's bootstrap secret was refused")
	}
	if tenant != "tenant_a" {
		t.Fatalf("issued under %q, want tenant_a", tenant)
	}
}

// ★ THE GUARD THAT MATTERS. A connector holding a valid secret for one organization's Site must not be able to
// be issued an identity under another's by naming it — that is the cross-organization shape the connector
// binding rule already refuses at register, and issuing it here would only move the failure later.
func TestASecretForOneOrganizationsSiteDoesNotEnrolIntoAnother(t *testing.T) {
	store := connectorTestSiteStore(t)
	seedSiteWithSecret(t, store, "tenant_a", "site-1", "s3cret-for-site-1")
	seedSiteWithSecret(t, store, "tenant_b", "site-b", "different-secret")

	if _, ok := connectorEnrolmentEligibility(context.Background(), store, "tenant_a",
		connectorReq("conn-1", "tenant_b", "site-1", "s3cret-for-site-1"), nil); ok {
		t.Fatal("tenant_a's Site secret was accepted as an enrolment into tenant_b")
	}
	// And the reverse direction: naming your own organization with somebody else's Site.
	if _, ok := connectorEnrolmentEligibility(context.Background(), store, "tenant_a",
		connectorReq("conn-1", "tenant_a", "site-b", "different-secret"), nil); ok {
		t.Fatal("tenant_b's Site was reachable by naming it from tenant_a")
	}
}

func TestAWrongOrAbsentSecretIsRefused(t *testing.T) {
	store := connectorTestSiteStore(t)
	seedSiteWithSecret(t, store, "tenant_a", "site-1", "s3cret-for-site-1")

	for _, tc := range []struct {
		name             string
		tenant, site, sc string
	}{
		{"wrong secret", "tenant_a", "site-1", "not-the-secret"},
		{"no secret", "tenant_a", "site-1", ""},
		{"no site", "tenant_a", "", "s3cret-for-site-1"},
		{"no organization", "", "site-1", "s3cret-for-site-1"},
		{"unknown site", "tenant_a", "site-does-not-exist", "s3cret-for-site-1"},
	} {
		if _, ok := connectorEnrolmentEligibility(context.Background(), store, "tenant_a",
			connectorReq("conn-1", tc.tenant, tc.site, tc.sc), nil); ok {
			t.Fatalf("%s: accepted", tc.name)
		}
	}
}

// A deployment with no Site store has issued no bootstrap secret, so no connector can be eligible. Asserted
// because the alternative — treating "nothing to check against" as "nothing objected" — is the two-zeroes
// shape that has bitten four gates in this tree.
func TestWithNoSiteStoreNoConnectorIsEligible(t *testing.T) {
	if _, ok := connectorEnrolmentEligibility(context.Background(), nil, "tenant_a",
		connectorReq("conn-1", "tenant_a", "site-1", "any-secret"), nil); ok {
		t.Fatal("a connector was admitted by a deployment that holds no Sites")
	}
}

// Every other eligibility mode passes straight through, so adding this one cannot have changed what a device
// enrolment does.
func TestOtherEligibilityModesAreNotConnectorEnrolments(t *testing.T) {
	store := connectorTestSiteStore(t)
	seedSiteWithSecret(t, store, "tenant_a", "site-1", "s3cret-for-site-1")
	for _, mode := range []string{"token", "idp", "mdm", "interactive", ""} {
		req := connectorReq("conn-1", "tenant_a", "site-1", "s3cret-for-site-1")
		req.Eligibility.Mode = mode
		if _, ok := connectorEnrolmentEligibility(context.Background(), store, "tenant_a", req, nil); ok {
			t.Fatalf("mode %q was handled as a connector enrolment", mode)
		}
	}
}

// ★ THE CALL SITE, NOT THE HELPER. Go compiles an unused function without complaint, and a correct rule that
// nothing consults is worth nothing — this tree has been bitten by exactly that. This asserts the enrol
// endpoint's eligibility chain actually reaches the connector mode, by reading the source of the chain.
func TestTheEnrolEndpointConsultsTheConnectorMode(t *testing.T) {
	src := readSourceFile(t, "enroll_endpoint.go")
	if !strings.Contains(src, "connectorEnrolmentEligibility(") {
		t.Fatal("enroll_endpoint.go never calls connectorEnrolmentEligibility: the connector mode is dead code " +
			"and the printed 'Add connector' command cannot bring a connector up")
	}
	if !strings.Contains(src, "connectorEligibilityMode") {
		t.Fatal("enroll_endpoint.go does not branch on connectorEligibilityMode")
	}
	// And it must sit BEFORE the shared-token comparison, or a connector's bootstrap secret would first be
	// tried as a device eligibility token.
	if strings.Index(src, "connectorEnrolmentEligibility(") > strings.Index(src, "ConstantTimeCompare([]byte(req.Eligibility.Token)") {
		t.Fatal("the connector mode is checked after the shared device token: a connector's Site secret would " +
			"be tried as a device credential first")
	}
}

// The Console's printed command must not go back to asking the operator to fill in a certificate path.
func TestTheAddConnectorCommandHasNoBlanksToFillIn(t *testing.T) {
	cmd := adminSiteEnrollmentCommand("TOKEN-VALUE", "/var/lib/dsse-connector")
	if strings.Contains(cmd, "<") || strings.Contains(cmd, "your connector") {
		t.Fatalf("the printed command still contains a placeholder:\n%s", cmd)
	}
	for _, want := range []string{"dsse-connector", "--token TOKEN-VALUE", "--state-dir /var/lib/dsse-connector"} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("the printed command lost %q:\n%s", want, cmd)
		}
	}
}

func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
