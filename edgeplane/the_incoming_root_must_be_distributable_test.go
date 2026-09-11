package edgeplane

import (
	"strings"
	"testing"
	"time"
)

// ★★★ THE ONE ROOT DEVICES ARE ASKED TO ADOPT WAS THE ONE NOTHING COULD HAND THEM (2026-08-27, found while
// building the channel that delivers these to a Mac).
//
// The discipline for replacing an organization's interception authority is announce, MEASURE, switch,
// withdraw — an agent reports which of the ANNOUNCED roots it found in its own trust store, and the
// withdrawal gate reads those reports. So a device has to be able to GET the incoming root before the switch;
// that is the whole point of announcing ahead.
//
// OfflineTenantAnnouncedRootFingerprints says "the one in force, any announced ahead of it, and any being
// retired". The distribution route beside it — the admin surface that carries the certificates themselves —
// carried the root in force and the retiring ones, and NOT the incoming one. Its own comment says the PEM
// "is available from the distribution routes that exist for handing it out"; for this root there was none.
//
// So the announcement asked every device to look for a fingerprint, and the only way to satisfy it was for
// somebody to have been handed the file by other means. The measurement would read "0 of N devices hold it"
// forever, and the honest reading of that is not "the devices are slow" — it is that nothing was ever
// delivered.
func TestTheRootAnOrganizationIsMovingToCanBeHandedToItsDevices(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	rootPEM, interPEM, keyPEM, _ := tenantOfflineBundle(t, "tenant_probe", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_probe", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load the authority in force: %v", err)
	}
	incomingRootPEM, _, _, _ := tenantOfflineBundle(t, "tenant_probe_next", now)
	incoming, err := interception.AnnounceTenantInterceptionRoot("tenant_probe", incomingRootPEM)
	if err != nil {
		t.Fatalf("announce the incoming root: %v", err)
	}

	rows := interception.ListOfflineTenantIntermediates()
	if len(rows) != 1 {
		t.Fatalf("expected one organization, got %d", len(rows))
	}
	row := rows[0]

	// Every fingerprint this organization's devices are told to look for must have a certificate here, or the
	// announcement is an instruction with nothing behind it.
	wanted := interception.OfflineTenantAnnouncedRootFingerprints("tenant_probe")
	if len(wanted) < 2 {
		t.Fatalf("the announcement names %d root(s); this test needs the overlap it was written for", len(wanted))
	}
	have := map[string]bool{}
	if row.RootSHA256 != "" {
		have[strings.ToLower(row.RootSHA256)] = true
	}
	for _, r := range row.Retiring {
		have[strings.ToLower(r.SHA256)] = true
	}
	for _, r := range row.Incoming {
		if strings.TrimSpace(r.PEM) == "" {
			t.Errorf("the incoming root %q is listed with no certificate, so it still cannot be delivered", r.CommonName)
		}
		have[strings.ToLower(r.SHA256)] = true
	}
	for _, fp := range wanted {
		if !have[strings.ToLower(fp)] {
			t.Errorf("this organization's devices are told to look for root %s and no distribution route "+
				"carries it — the adoption measurement can never move off zero", fp)
		}
	}
	if len(row.Incoming) != 1 || row.Incoming[0].CommonName != incoming.Subject.CommonName {
		t.Errorf("the root being moved TO is not named as such: %+v", row.Incoming)
	}
}

// ★ THE CONTROL: an organization that is not moving anywhere lists no incoming root. An empty overlap must
// read as empty, or every screen shows a rotation that is not happening.
func TestAnOrganizationThatIsNotMovingListsNoIncomingRoot(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	interception, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	rootPEM, interPEM, keyPEM, _ := tenantOfflineBundle(t, "tenant_probe", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_probe", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load: %v", err)
	}
	rows := interception.ListOfflineTenantIntermediates()
	if len(rows) != 1 || len(rows[0].Incoming) != 0 {
		t.Fatalf("an organization with no replacement in progress lists an incoming root: %+v", rows)
	}
}
