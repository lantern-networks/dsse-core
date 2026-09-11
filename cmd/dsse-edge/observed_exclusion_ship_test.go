package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/logs"
)

// A store that only records, so these measure what ARRIVES rather than what a real store then does with it.
type recordingObservedStore struct {
	entries []observedExclusionEntry
}

func (s *recordingObservedStore) Record(e observedExclusionEntry) { s.entries = append(s.entries, e) }
func (s *recordingObservedStore) Query(string, observedQueryFilter) observedQueryResult {
	return observedQueryResult{}
}
func (s *recordingObservedStore) ByApp(string, int) observedByAppResult { return observedByAppResult{} }
func (s *recordingObservedStore) TransportCAReadiness(string, string, []string) transportCAReadiness {
	return transportCAReadiness{}
}
func (s *recordingObservedStore) RecoveryNameReadiness(string, string, []string) recoveryNameReadiness {
	return recoveryNameReadiness{}
}
func (s *recordingObservedStore) TransportCAReadinessAtSerial(string, string, []string, int64) transportCAReadiness {
	return transportCAReadiness{}
}

func sampleReport() observedExclusionEntry {
	return observedExclusionEntry{
		TenantID:               "tenant_a",
		DeviceIdentity:         "mac-dev-1",
		DeviceGroup:            "default",
		Platform:               "macos",
		EffectiveAppSigningIDs: []string{"com.example.one", "com.example.two"},
		AdminAppSigningIDs:     []string{"com.example.one"},
		UnmanagedAppSigningIDs: []string{"com.example.two"},
		ReportedAt:             time.Now().UTC().Truncate(time.Second),
	}
}

// The report reaches the control plane through the shipped stream, with the fields an operator reads intact.
func TestADeviceReportSurvivesTheTripToTheControlPlane(t *testing.T) {
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	shipObservedExclusion(writer, sampleReport())

	raw, err := os.ReadFile(filepath.Join(dir, observedExclusionShipStream))
	if err != nil {
		t.Fatalf("the report was never written to the shipped stream: %v", err)
	}
	line := strings.TrimSpace(strings.Split(strings.TrimSpace(string(raw)), "\n")[0])

	store := &recordingObservedStore{}
	recordShippedObservedExclusion(store, observedExclusionShipStream, []byte(line))
	if len(store.entries) != 1 {
		t.Fatalf("the control plane recorded %d report(s), want 1", len(store.entries))
	}
	got := store.entries[0]
	if got.TenantID != "tenant_a" || got.DeviceIdentity != "mac-dev-1" {
		t.Fatalf("the report arrived as %q/%q", got.TenantID, got.DeviceIdentity)
	}
	// ★ THE SETS, not just the names. A report that arrives with its identity and an empty exclusion set is
	// worse than one that does not arrive: every screen shows a device reporting nothing at all.
	if len(got.EffectiveAppSigningIDs) != 2 || len(got.UnmanagedAppSigningIDs) != 1 {
		t.Fatalf("effective=%v unmanaged=%v: the sets did not survive the trip",
			got.EffectiveAppSigningIDs, got.UnmanagedAppSigningIDs)
	}
	if got.Platform != "macos" || got.DeviceGroup != "default" {
		t.Fatalf("platform=%q group=%q", got.Platform, got.DeviceGroup)
	}
}

// Records from other streams are not device reports, and this path carries every shipped record in the
// deployment. Folding one by mistake would put invented rows in the durable copy.
func TestOnlyTheReportStreamIsFoldedIntoTheObservedStore(t *testing.T) {
	row, _ := json.Marshal(sampleReport())
	for _, stream := range []string{"audit.log.jsonl", "device_state.log.jsonl", "access.log.jsonl", ""} {
		store := &recordingObservedStore{}
		recordShippedObservedExclusion(store, stream, row)
		if len(store.entries) != 0 {
			t.Fatalf("a %q record was folded into the observed-exclusion store", stream)
		}
	}
}

// A record naming neither an organization nor a device cannot be filed against anything, and storing it puts a
// row in the durable copy that no screen can show.
func TestAReportThatNamesNobodyIsNotStored(t *testing.T) {
	for _, body := range []string{
		`{"tenant_id":"","device_identity":"mac-dev-1"}`,
		`{"tenant_id":"tenant_a","device_identity":""}`,
		`not json at all`,
	} {
		store := &recordingObservedStore{}
		recordShippedObservedExclusion(store, observedExclusionShipStream, []byte(body))
		if len(store.entries) != 0 {
			t.Fatalf("stored an unattributable report: %s", body)
		}
	}
}

// ★★★ THE STREAM HAS TO BE SHIPPED. A stream the Edge writes and the shipper does not carry is a file that
// grows on the Edge and reaches nobody — which is exactly the "written correctly, delivered to no one" shape
// this whole sequence of work keeps finding.
func TestTheReportStreamIsOneTheShipperCarries(t *testing.T) {
	for _, s := range defaultAuditShipStreams {
		if s == observedExclusionShipStream {
			return
		}
	}
	t.Fatalf("%q is not in defaultAuditShipStreams: the Edge writes device reports and nothing carries them "+
		"to the control plane", observedExclusionShipStream)
}

// And the report handler actually ships. Go compiles an unused function without complaint, and a correct
// shipper nothing calls is worth nothing.
func TestTheReportHandlerShipsWhatItRecords(t *testing.T) {
	src := readSourceFile(t, "steer_agent_policy_routes.go")
	if !strings.Contains(src, "shipObservedExclusion(") {
		t.Fatal("the device-report handler records locally and ships nothing: the durable copy would still have " +
			"to come from the Edge's own database")
	}
	if strings.Index(src, "config.ObservedExclusions.Record(reportEntry)") < 0 {
		t.Fatal("the handler no longer records into this node's own view")
	}
	// The receiver has to fold it, or the shipment arrives and is dropped.
	if !strings.Contains(readSourceFile(t, "audit_ingest_receiver.go"), "recordShippedObservedExclusion(") {
		t.Fatal("the ingest receiver never folds a shipped device report")
	}
}
