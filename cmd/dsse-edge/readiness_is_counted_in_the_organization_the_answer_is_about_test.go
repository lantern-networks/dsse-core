package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// ★★★ A DEVICE THAT REPORTED EVERY MINUTE READ AS NEVER HAVING REPORTED (2026-09-07, measured on wakaba.lab
// with a real Mac steering and being inspected).
//
// The device's own journal said the report landed — status 204, once a minute. The Edge's observed record
// held it: posture steering, the organization's own transport CA pinned, the current adopted serial, the name
// it sends, timestamped seconds earlier. And the readiness beside it said:
//
//	silent: [shinnomac-mini]  never_reported_anything: [shinnomac-mini]  ready_pct: 0  safe_to_cut: false
//
// The anchors and the device list came from the organization the caller asked about; the readiness was looked
// up in the NODE's own organization, whose report list is empty on any deployment whose customers are
// somebody else. Withdrawing an organization's shared anchor is the decision this number exists to support,
// and it could never be taken.
func TestReadinessIsCountedInTheOrganizationTheAnswerIsAbout(t *testing.T) {
	store := newObservedExclusionStore(0)
	customer, operator := "tenant_customer", "tenant_default"
	fp := strings.Repeat("ab", 32)

	store.Record(observedExclusionEntry{
		TenantID:                customer,
		DeviceIdentity:          "ShinnoMac-mini",
		Platform:                "macos",
		Posture:                 "steering",
		PinnedTransportCASHA256: []string{fp},
		AdoptedTrustSerial:      14,
		ReportedAt:              time.Now().UTC(),
	})
	known := []string{"ShinnoMac-mini"}

	own := store.TransportCAReadinessAtSerial(customer, fp, known, 14)
	if len(own.Ready) != 1 || len(own.NeverReportedAnything) != 0 {
		t.Fatalf("asked about its own organization the device is ready: ready=%v silent=%v never=%v",
			own.Ready, own.Silent, own.NeverReportedAnything)
	}

	// The same device, the same instant, asked about the node's organization.
	elsewhere := store.TransportCAReadinessAtSerial(operator, fp, known, 14)
	if len(elsewhere.NeverReportedAnything) != 1 {
		t.Fatalf("this control is meant to show the wrong-organization answer, got %+v", elsewhere)
	}
	if elsewhere.SafeToCut {
		t.Error("an empty denominator must never read as safe to cut")
	}
}

// ★ AND ON THE CALL SITE, because that is where the defect was: the store was always right and the screen
// asked it the wrong question. A behavioural test of the store alone passes with the screen still broken.
func TestTheAnchorsScreenAnswersAboutOneOrganization(t *testing.T) {
	raw, err := os.ReadFile("admin_transport_trust_anchors.go")
	if err != nil {
		t.Fatalf("read the route: %v", err)
	}
	src := string(raw)
	if strings.Contains(src, "readiness := anchorCoverage(config, tenantID, fp, known)") {
		t.Error("the anchors screen lists `target`'s certificates over `target`'s devices and computes " +
			"readiness in the node's own organization — every customer device reads as never having reported")
	}
	if !strings.Contains(src, "readiness := anchorCoverage(config, target, fp, known)") {
		t.Error("the readiness call no longer names the organization the answer is about")
	}
}
