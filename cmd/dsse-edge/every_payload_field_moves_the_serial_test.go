package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ★★★ THE INVARIANT THE AGENTS DEPEND ON, WRITTEN DOWN AS A GATE (2026-08-20, proposed from win-dev-1 after it
// spent a day holding an anchor the Edge had already withdrawn).
//
// A device's adoption gate compares ONE thing: the serial. It never compares the content. So a distribution
// whose content changes without the serial advancing is not "late" — it is INVISIBLE. The device reports
// itself up to date, holds the old set for ever, and every gate that reads those reports opens on false
// evidence. Measured twice in one day, both times as an anchor that stayed on devices after it had left the
// bundle.
//
// The rule is therefore: everything the payload carries must be represented in the announcement string that
// decides whether the serial advances. The announcement block says so in its own comment; this counts.
//
// Fields the announcement cannot and must not carry are named here with their reason, because an exemption is
// a field this gate stops watching.
func TestEveryTrustBundlePayloadFieldCanMoveTheSerial(t *testing.T) {
	payload, err := os.ReadFile("../../agentpolicy/trust_bundle.go")
	if err != nil {
		t.Fatal(err)
	}
	announcement, err := os.ReadFile("steer_agent_policy_routes.go")
	if err != nil {
		t.Fatal(err)
	}

	body := string(payload)
	start := strings.Index(body, "type TrustBundlePayload struct {")
	if start < 0 {
		t.Fatal("TrustBundlePayload is not where this gate looks — point it at the type rather than leaving a " +
			"gate that reads nothing")
	}
	body = body[start:]
	if end := strings.Index(body, "\n}"); end > 0 {
		body = body[:end]
	}

	// The announcement block, not the whole file: a mention anywhere else is not a reason the serial moves.
	block := string(announcement)
	from := strings.Index(block, "recomputeAnnouncement := func()")
	if from < 0 {
		t.Fatal("the announcement is no longer computed where this gate looks")
	}
	block = block[from:]
	if to := strings.Index(block, "\n\t\t}\n\t\trecomputeAnnouncement()"); to > 0 {
		block = block[:to]
	}

	// Fields whose change is either impossible without another field moving, or which ARE the serial.
	exempt := map[string]string{
		"schema_version": "the shape of the document, not its content; a change here is a code change and the " +
			"serial floor moves with the deployment",
		"tenant_id": "identifies WHOSE bundle this is — it is the key, not a value that can change under a device",
		"serial":    "the thing being decided",
		"issued_at": "informational and deliberately not what rollback protection rests on (see the field's own " +
			"comment); it changes on every signature and would make every bundle look new",
		"transport_ca_pem": "the anchors themselves, represented in the announcement as one fingerprint token " +
			"per organization plus the shared-anchor withdrawal token",
		"interception_root_sha256": "the interception roots, represented by " +
			"interceptionRootFingerprintsForTenant at the top of the block",
		"agent_policy_public_keys":  "represented as policy-keys=",
		"transport_server_name":     "represented by ServerNameAnnouncements as tenant@name",
		"renewal_recovery_sni":      "represented as recovery-sni=, including its withdrawal",
		"renewal_recovery_endpoint": "represented as recovery-endpoint=",
	}

	missing := []string{}
	for _, m := range regexp.MustCompile("`json:\"([a-z_0-9]+)").FindAllStringSubmatch(body, -1) {
		field := m[1]
		if _, ok := exempt[field]; ok {
			continue
		}
		if strings.Contains(block, field) {
			continue
		}
		missing = append(missing, field)
	}
	if len(missing) > 0 {
		t.Fatalf("the trust bundle carries %d field(s) that can change without the serial advancing:\n    %s\n"+
			"A device compares only the serial, so a change these make is not late — it is invisible, and the "+
			"device reports itself up to date while holding the previous answer. Add each to the announcement "+
			"in steer_agent_policy_routes.go, or name it in this gate's exemption list with the reason.",
			len(missing), strings.Join(missing, "\n    "))
	}
	if len(exempt) == 0 {
		t.Fatal("no field is exempt, which means this gate is not reading the type it thinks it is")
	}
}
