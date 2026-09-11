package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ★★★ A REPORTED FIELD WITH NO READER IS THE SAME SILENCE AS NO FIELD — TWICE, ONE DAY APART (2026-08-20).
//
// renewal_recovery_sni_sent went unread in August: Windows shipped it, macOS shipped it, the Edge stored a
// struct that had the field, and every device still read as silent because the handler's own request struct
// never mentioned it. A test was written for that field, with a comment asking whoever adds the NEXT field to
// add a case. The next field — renewal_recovery_target — was added the following day, to the entry, to the
// Postgres column AND to the readiness rule, and not to the handler. Every device counted as silent for ever,
// the fold's measurement could never say "holds" about anybody, and the dedicated recovery port had already
// been closed underneath it.
//
// Asking people to remember did not work twice, so this counts instead: every json field the stored report
// carries must appear in the file that decodes what devices send. It cannot check that the value is COPIED —
// TestWhatTheDeviceReportsReachesTheStore does that, field by field, and this is what tells you to go add a
// case there.
func TestEveryStoredReportFieldIsReadByTheHandler(t *testing.T) {
	entry, err := os.ReadFile("steer_exclusion_observed.go")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := os.ReadFile("steer_agent_policy_routes.go")
	if err != nil {
		t.Fatal(err)
	}

	// The stored report's own type, not the whole file: other types in here are not what a device sends.
	start := strings.Index(string(entry), "type observedExclusionEntry struct {")
	if start < 0 {
		t.Fatal("observedExclusionEntry is not where this gate looks — point it at the type rather than " +
			"leaving a gate that reads nothing")
	}
	body := string(entry)[start:]
	if end := strings.Index(body, "\n}"); end > 0 {
		body = body[:end]
	}

	// Fields the DEVICE cannot report: the Edge stamps or derives them itself. Kept short and explained,
	// because every entry here is a field this gate stops watching.
	stamped := map[string]bool{
		"tenant_id": true, "device_identity": true, "device_group": true, "reported_at": true,
		"admin_app_signing_ids": true, "server_app_signing_id_count": true, "server_initiated_rule_count": true,
		// Derived on the Edge by comparing what the device reports as effective against what the Edge
		// administered — a device cannot tell you which of its own exclusions nobody authorised.
		"unmanaged_app_signing_ids": true,
	}

	missing := []string{}
	for _, m := range regexp.MustCompile("`json:\"([a-z_0-9]+)").FindAllStringSubmatch(body, -1) {
		field := m[1]
		if stamped[field] || strings.Contains(string(handler), `"`+field+`"`) {
			continue
		}
		missing = append(missing, field)
	}
	if len(missing) > 0 {
		t.Fatalf("the stored device report carries %d field(s) the report handler never decodes:\n    %s\n"+
			"Whatever a device sends for these is discarded, and every gate that reads them decides on an empty "+
			"value for ever. Add them to the request struct in steer_agent_policy_routes.go, copy them into the "+
			"recorded entry, and add a case to TestWhatTheDeviceReportsReachesTheStore.",
			len(missing), strings.Join(missing, "\n    "))
	}
}
