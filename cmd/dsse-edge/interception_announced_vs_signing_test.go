package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// ★★★ THE POLICY DOCUMENT NAMED THE NODE'S ROOT WHILE THE ORGANIZATION'S OWN ROOT DID THE SIGNING
// (2026-08-19, reported from win-dev-1 and reproduced here).
//
// The agent fetches /steer/agent-policy every minute, and it carries the interception roots the device should
// look for in its own trust store. It asked nodeWideInterceptionRootFingerprints — which answers about the NODE
// — while an organization with an issuer of its own has its traffic signed under ITS root.
//
// What that cost, measured on the box: with steering armed, github.com arrived signed by "Lab Tenant
// Interception Issuing CA 2028" under "Lab Tenant Interception Root 2028", a root in no store on that machine.
// schannel refused it too, so every HTTPS request on the machine failed at once — browser, command line and
// platform TLS alike. The trust bundle had been asking per organization since 2026-08-18; this document had
// not, and one right answer beside one wrong answer is a wrong answer.
func TestTheAgentPolicyNamesTheRootThatSignsThisDevicesTraffic(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	interception, err := edgeplane.NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("interception: %v", err)
	}
	// Northwind signs under its own root. The node's organization (tenant_lab_001) keeps the node-wide anchor.
	rootPEM, interPEM, keyPEM := offlineTenantBundleForTest(t, "Northwind", now)
	if _, err := interception.LoadOfflineTenantIntermediate("tenant_northwind", rootPEM, interPEM, keyPEM); err != nil {
		t.Fatalf("load issuer: %v", err)
	}
	signingRoot := ""
	for _, issuer := range interception.ListOfflineTenantIntermediates() {
		if strings.EqualFold(issuer.Tenant, "tenant_northwind") {
			signingRoot = issuer.RootSHA256
		}
	}
	if signingRoot == "" {
		t.Fatal("the fixture produced no signing root for Northwind — nothing to compare")
	}

	ledger := enrolledinventory.NewLedger()
	stamp := now.Format(time.RFC3339)
	if _, err := ledger.Enroll("nw-laptop-1", "tenant_northwind", "", stamp); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	_, anchorPEM := tenantCATestCA(t, "Transport Anchor")
	config := serverConfig{
		Evaluator:              testEvaluator(), // node tenant = tenant_lab_001
		EnrolledLedger:         ledger,
		NetworkExtensionLabTLS: interception,
		AgentPolicySigner:      testAgentPolicySigner(t),
		TrustBundleCAPEM:       string(anchorPEM),
		TrustBundleSerial:      7,
		TenantIDForTrust:       "tenant_lab_001",
		AdminAuth:              newAdminAuthStore(),
	}
	handler := newServerWithConfig(config)

	rec := asVerifiedDevice(t, handler, "nw-laptop-1", "/steer/agent-policy")
	if rec.Code != 200 {
		t.Fatalf("agent policy: HTTP %d %s", rec.Code, rec.Body.String())
	}
	var env agentpolicy.Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	raw, derr := base64.StdEncoding.DecodeString(env.PayloadB64)
	if derr != nil {
		t.Fatalf("decode payload: %v", derr)
	}
	var payload struct {
		Roots []string `json:"interception_root_sha256"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode payload json: %v — %s", err, string(raw))
	}

	nodeWide := nodeWideInterceptionRootFingerprints(config)
	var told string
	for _, fp := range payload.Roots {
		told += fp + " "
		if strings.EqualFold(fp, signingRoot) {
			return // the device is told to look for the root its own traffic is signed under
		}
	}
	for _, fp := range nodeWide {
		if strings.Contains(told, fp) {
			t.Fatalf("Northwind's device is told to look for the NODE's root (%s) while its traffic is signed "+
				"under %s — with steering armed that machine loses every HTTPS request it makes",
				shortFingerprint(fp), shortFingerprint(signingRoot))
		}
	}
	t.Fatalf("Northwind's device was told to look for %q, and its traffic is signed under %s",
		strings.TrimSpace(told), shortFingerprint(signingRoot))
}

// ★ AND THE CHECK THAT SAYS SO CAN FAIL. The signal this replaces (interception_root_trust wanted=1 found=1)
// was green through the outage because it measured whether the box holds the ANNOUNCED root. A replacement
// that cannot be shown failing would be the same mistake with a new name, so both directions are asserted.
func TestTheAnnouncedVersusSigningCheckFiresAndIsQuietWhenItShould(t *testing.T) {
	matching := []interceptionAnnouncement{{
		Tenant: "tenant_northwind", RootCommonName: "Northwind Interception Root 2028",
		SigningSHA256: "aaaa1111", Announced: []string{"aaaa1111"},
	}}
	if got := interceptionAnnouncementMismatchLines(matching); len(got) != 0 {
		t.Fatalf("an organization told to look for the root that signs its traffic was reported as a mismatch: %v", got)
	}

	// The outage, in its measured shape: the device is told the deployment-wide root and the traffic is signed
	// under the organization's own.
	drifted := []interceptionAnnouncement{{
		Tenant: "tenant_reference_lab", RootCommonName: "Lab Tenant Interception Root 2028",
		SigningSHA256: "0ac681cd04f2d317", Announced: []string{"3697366977a5"},
	}}
	got := interceptionAnnouncementMismatchLines(drifted)
	if len(got) != 1 {
		t.Fatalf("the drift that took a machine off the network was not reported: %v", got)
	}
	if !strings.Contains(got[0], "tenant_reference_lab") || !strings.Contains(got[0], "0ac681cd") {
		t.Fatalf("the finding does not name the organization and the root that signs: %q", got[0])
	}

	// Told NOTHING is the same outage wearing a quieter face, and must not read as agreement.
	silent := []interceptionAnnouncement{{
		Tenant: "tenant_acme", RootCommonName: "Acme Interception Root", SigningSHA256: "bbbb2222",
	}}
	if got := interceptionAnnouncementMismatchLines(silent); len(got) != 1 || !strings.Contains(got[0], "nothing at all") {
		t.Fatalf("an organization told to look for no root at all was not reported: %v", got)
	}

	// A signing root the node cannot read is unknown, not fine.
	unreadable := []interceptionAnnouncement{{
		Tenant: "tenant_acme", IntermediateCN: "Acme Interception Issuing CA", Announced: []string{"cccc3333"},
	}}
	if got := interceptionAnnouncementMismatchLines(unreadable); len(got) != 1 {
		t.Fatalf("an organization whose signing root could not be read was passed as a match: %v", got)
	}
}
