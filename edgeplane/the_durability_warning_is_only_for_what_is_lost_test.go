package edgeplane

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

// ★★★ A WARNING EVERY DEPLOYMENT IS EXPECTED TO IGNORE (2026-08-27, read in the log of an Edge that had just
// correctly assembled itself).
//
//	WARNING offline_tenant_intermediate_not_durable tenant="…"
//	err=no -interception-offline-tenant-intermediate-dir is configured
//	(live now; a restart returns this organization to REFUSED until it is loaded again)
//
// Not having a directory is a problem when an operator placed these files here by hand: a restart loses them.
// It is the CORRECT shape when the node fetches its organizations from the control plane at start-up, which
// is what the installer now produces — the restart re-fetches, and what is being kept off this disk is a
// short-lived signing key on a node that may not exist tomorrow. The sentence describes a state that cannot
// happen on that node.
//
// A warning an operator is expected to ignore is worse than none: it is the one that teaches them to ignore
// the next.
func TestANodeThatFetchesItsOrganizationsIsNotWarnedAboutNotStoringThem(t *testing.T) {
	logged := captureInterceptionLog(t)
	interception := newInterceptionForDurabilityTest(t)
	interception.OfflineTenantMaterialIsFetched()
	loadOneTenantAuthority(t, interception, "tenant_probe")

	if strings.Contains(logged(), "offline_tenant_intermediate_not_durable") {
		t.Errorf("a node that re-fetches this on every start was warned that a restart loses it:\n%s", logged())
	}
	// ★ AND IT STILL SAYS WHAT IT LOADED. Silencing the warning must not silence the record of which
	// authority this node is now signing that organization under.
	if !strings.Contains(logged(), "offline_tenant_intermediate_loaded") {
		t.Errorf("the load itself is no longer reported:\n%s", logged())
	}
}

// ★★ THE CONTROL, AND IT IS THE CASE THE WARNING WAS WRITTEN FOR. A node whose material was placed on it by
// hand loses it on a restart and must still be told.
func TestANodeHoldingHandPlacedMaterialIsStillWarned(t *testing.T) {
	logged := captureInterceptionLog(t)
	interception := newInterceptionForDurabilityTest(t)
	loadOneTenantAuthority(t, interception, "tenant_probe")

	if !strings.Contains(logged(), "offline_tenant_intermediate_not_durable") {
		t.Errorf("a node that will lose this on a restart was not warned:\n%s", logged())
	}
}

// captureInterceptionLog collects what the package logs during one test. The behaviour under test IS a log
// line, so nothing weaker would measure it.
func captureInterceptionLog(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	previousOut, previousFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(previousOut); log.SetFlags(previousFlags) })
	return buf.String
}

// newInterceptionForDurabilityTest builds an engine with NO intermediate directory, which is the state both
// tests are about.
func newInterceptionForDurabilityTest(t *testing.T) *NetworkExtensionLabTLSInterception {
	t.Helper()
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	return interception
}

func loadOneTenantAuthority(t *testing.T, interception *NetworkExtensionLabTLSInterception, tenant string) {
	t.Helper()
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	rootPEM, interPEM, keyPEM, _ := tenantOfflineBundle(t, tenant, now)
	if _, err := interception.LoadOfflineTenantIntermediate(tenant, rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load %s: %v", tenant, err)
	}
}
