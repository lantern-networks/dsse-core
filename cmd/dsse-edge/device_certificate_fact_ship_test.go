package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/logs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func factOf(identity, anchor, serial, seen string) deviceCertificateFact {
	return deviceCertificateFact{Identity: identity, AnchorSHA256: anchor, Serial: serial, LastSeenAt: seen}
}

// The fleet's view is what the withdrawal gate reads, so a fact observed on one node has to arrive intact on
// the node that answers.
func TestAShippedCertificateFactArrivesWithWhatTheGateReads(t *testing.T) {
	deviceCertificates = &deviceCertificateFacts{by: map[string]deviceCertificateFact{}}
	row, _ := json.Marshal(factOf("mac-dev-1", "anchor-a", "42", "2026-08-23T01:00:00Z"))
	recordShippedDeviceCertificateFact(deviceCertificateFactStream, row)

	got := deviceCertificates.snapshot()
	if len(got) != 1 {
		t.Fatalf("the control plane holds %d fact(s), want 1 — the withdrawal gate would say nobody has ever "+
			"presented a certificate", len(got))
	}
	// ★ THE ANCHOR ABOVE ALL. Without it the gate cannot tell "still admitted under the CA you are retiring"
	// from "admitted under a different one", and treats the device as unseen — which blocks every withdrawal.
	if got[0].AnchorSHA256 != "anchor-a" || got[0].Serial != "42" {
		t.Fatalf("arrived as anchor=%q serial=%q", got[0].AnchorSHA256, got[0].Serial)
	}
}

// ★★★ A REPLAY MUST NOT REINSTATE AN OLD CERTIFICATE. The spool replays after a control-plane outage, so a
// batch can arrive after a fresher observation — and for this gate that would mean blocking a retirement on
// evidence that stopped being true.
func TestAnOlderObservationArrivingLateDoesNotWin(t *testing.T) {
	deviceCertificates = &deviceCertificateFacts{by: map[string]deviceCertificateFact{}}
	newer, _ := json.Marshal(factOf("mac-dev-1", "anchor-new", "99", "2026-08-23T02:00:00Z"))
	older, _ := json.Marshal(factOf("mac-dev-1", "anchor-old", "42", "2026-08-23T01:00:00Z"))
	recordShippedDeviceCertificateFact(deviceCertificateFactStream, newer)
	recordShippedDeviceCertificateFact(deviceCertificateFactStream, older)

	if got := deviceCertificates.snapshot(); got[0].AnchorSHA256 != "anchor-new" {
		t.Fatalf("anchor=%q: a replayed older observation overwrote a fresher one, so the gate would block a "+
			"retirement on a certificate the device has already replaced", got[0].AnchorSHA256)
	}
}

// A fact that cannot name an anchor must not erase one an earlier observation carried — the same rule the local
// path follows, for the same reason: a fact that flickers is worse for a gate than one that is absent.
func TestAnAnchorlessFactDoesNotEraseAKnownAnchor(t *testing.T) {
	deviceCertificates = &deviceCertificateFacts{by: map[string]deviceCertificateFact{}}
	with, _ := json.Marshal(factOf("mac-dev-1", "anchor-a", "42", "2026-08-23T01:00:00Z"))
	without, _ := json.Marshal(factOf("mac-dev-1", "", "43", "2026-08-23T02:00:00Z"))
	recordShippedDeviceCertificateFact(deviceCertificateFactStream, with)
	recordShippedDeviceCertificateFact(deviceCertificateFactStream, without)

	if got := deviceCertificates.snapshot(); got[0].AnchorSHA256 != "anchor-a" {
		t.Fatalf("anchor=%q: an observation that could not name the anchor erased one that could", got[0].AnchorSHA256)
	}
}

// Records from other streams are not certificate facts, and this path carries every shipped record.
func TestOnlyTheCertificateFactStreamIsFolded(t *testing.T) {
	deviceCertificates = &deviceCertificateFacts{by: map[string]deviceCertificateFact{}}
	row, _ := json.Marshal(factOf("mac-dev-1", "anchor-a", "42", "2026-08-23T01:00:00Z"))
	for _, stream := range []string{"audit.log.jsonl", "device_state.log.jsonl", observedExclusionShipStream, ""} {
		recordShippedDeviceCertificateFact(stream, row)
	}
	if got := deviceCertificates.snapshot(); len(got) != 0 {
		t.Fatalf("a record from another stream was folded in as a certificate fact: %v", got)
	}
}

// ★★★ SHIPPED ON CHANGE, NOT ON EVERY HANDSHAKE. This is observed on the (T) handshake — shipping each one
// would put a record on the wire every time any device reconnects. What the gate needs changes on a renewal or
// a re-enrolment, and that is what the comparison keys on.
func TestTheFactIsShippedOnChangeAndNotOnEveryHandshake(t *testing.T) {
	src := readSourceFile(t, "device_certificate_facts.go")
	if !strings.Contains(src, "shipDeviceCertificateFact(") {
		t.Fatal("nothing ships the certificate fact: a control plane sees no handshakes, so the device-CA " +
			"withdrawal gate would refuse every withdrawal forever")
	}
	if !strings.Contains(src, "previous.AnchorSHA256 != fact.AnchorSHA256 || previous.Serial != fact.Serial") {
		t.Fatal("the fact is shipped without comparing it to the previous one: every handshake in the " +
			"deployment would put a record on the wire")
	}
	if !strings.Contains(readSourceFile(t, "audit_ingest_receiver.go"), "recordShippedDeviceCertificateFact(") {
		t.Fatal("the ingest receiver never folds a shipped certificate fact")
	}
	shipped := false
	for _, s := range defaultAuditShipStreams {
		if s == deviceCertificateFactStream {
			shipped = true
		}
	}
	if !shipped {
		t.Fatalf("%q is not carried by the shipper: the Edge would write it and reach nobody", deviceCertificateFactStream)
	}
}

// ★★★ CHANGE-ONLY SHIPPING LEAVES THE CONTROL PLANE EMPTY AFTER ITS OWN RESTART. Its copy of this is in
// memory — correct for an Edge, which re-observes every device within seconds, and wrong for a node that
// terminates no handshakes at all. Without a re-ship the withdrawal gate goes back to refusing every
// retirement, which is the defect this whole file exists to end.
//
// Measured the same day in the other direction too: the Edge came up first, the older control-plane binary
// answered 400 to a stream it did not know, and those records went to the refused spool — permanently, because
// a refusal is not retried and the fact would not change again for weeks.
func TestEverythingIsResentPeriodicallyAndNotOnlyOnChange(t *testing.T) {
	src := readSourceFile(t, "device_certificate_fact_ship.go")
	if !strings.Contains(src, "func reshipDeviceCertificateFacts()") {
		t.Fatal("nothing re-sends the facts: a control-plane restart would empty the fleet's view for good, " +
			"and a single refused shipment would never be retried")
	}
	if !strings.Contains(readSourceFile(t, "main.go"), "startDeviceCertificateReship()") {
		t.Fatal("the periodic re-ship is never started")
	}
}

// ★★★ A FACT THAT NAMES NO ORGANIZATION CANNOT BE SHIPPED (2026-08-23, measured). The control plane refuses a
// record from an identified Edge that is filed under nobody — 403, "a shipment from an identified edge cannot
// be filed under none" — and it is right to: a record belonging to no organization lands in the partition
// everybody reads. The fact simply had no tenant on it, because until it was shipped it never left the node
// that observed it. Live, the Edge shipped and was refused six times before this was added.
func TestAnObservedCertificateNamesTheOrganizationItBelongsTo(t *testing.T) {
	src := readSourceFile(t, "device_certificate_facts.go")
	if !strings.Contains(src, `TenantID string \x60json:"tenant_id,omitempty"\x60`) &&
		!strings.Contains(src, "TenantID string") {
		t.Fatal("the observed certificate fact carries no organization: every shipment is refused 403 and the " +
			"control plane's view stays empty")
	}
	// And it must come from the chain, never from anything the device sends — the rule the transport follows.
	if !strings.Contains(src, "TenantForVerifiedChains(chains)") {
		t.Fatal("the organization on an observed certificate is not taken from the verified chain")
	}
	if !strings.Contains(readSourceFile(t, "main.go"), "setDeviceCertificateTenantRegistry(") {
		t.Fatal("nothing arms tenant attribution, so every observed fact names no organization")
	}
}

func TestPeriodicCertificateFactsKeepObservedTimeWithoutRenewal(t *testing.T) {
	if deviceCertificateReshipEvery > pkiAdoptionFreshFor/2 {
		t.Fatal("unchanged certificates become stale before periodic observation shipping")
	}
	oldFacts, oldWriter := deviceCertificates, deviceCertificateShipWriter.Load()
	t.Cleanup(func() { deviceCertificates = oldFacts; deviceCertificateShipWriter.Store(oldWriter) })
	deviceCertificates = &deviceCertificateFacts{by: map[string]deviceCertificateFact{}}
	dir := t.TempDir()
	writer, err := logs.NewWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	deviceCertificateShipWriter.Store(writer)
	start := time.Now().UTC().Truncate(time.Second)
	cert, _, _ := deviceAdmissionTestCA(t, "unchanged observed certificate")
	deviceCertificates.observe("online", cert, start)
	deviceCertificates.observe("offline", cert, start)
	// Same serial and anchor, several freshness windows later. The first online
	// record alone is now too old, so periodic shipping must carry the new sighting.
	latest := start.Add(3 * pkiAdoptionFreshFor)
	deviceCertificates.observe("online", cert, latest)
	reshipDeviceCertificateFacts()
	data, err := os.ReadFile(filepath.Join(dir, deviceCertificateFactStream))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	scan := bufio.NewScanner(bytes.NewReader(data))
	for scan.Scan() {
		var f deviceCertificateFact
		if err := json.Unmarshal(scan.Bytes(), &f); err != nil {
			t.Fatal(err)
		}
		seen[f.Identity] = f.LastSeenAt
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if seen["online"] != latest.Format(time.RFC3339) {
		t.Fatal("unchanged certificate's new observation not shipped")
	}
	if seen["offline"] != start.Format(time.RFC3339) {
		t.Fatal("replay fabricated freshness for an offline device")
	}
}
