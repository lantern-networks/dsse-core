package main

import (
	"os"
	"strings"
	"testing"
)

// ★★★ A CONTROL-PLANE PAIR HELD TWO DIFFERENT ANSWERS (2026-08-29, measured on a two-region deployment: an
// operator authored a steering exclusion in the Console, the control planes were recreated, and one of them
// logged "loaded 1 policy(ies) from the durable store" while the other logged "loaded 0"). The Console reads
// whichever answers, so the exclusion existed on refresh and did not on the next one — and the profile issued
// to a device carried four identifiers or none depending on which node signed it.
//
// The cause is narrow and repeats: -steer-exclusion-store defaults to "memory", nothing in the generated
// deployment set it, and the automatic fallback that rescues most stores does not apply to this one (it is not
// resolved by the CP-state blob persister, so it is not on storeUnderstandsSharedState). A store nobody names
// is a store each node answers for itself.
//
// This is the same shape as the agent catalogue and the rollout plan, both found the day before. So the list
// is asserted rather than remembered: a control plane must NAME the stores that hold what an operator authors.
func TestTheGeneratedControlPlaneNamesEveryStoreItMustShare(t *testing.T) {
	body, err := os.ReadFile("launch.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	// ★ THE WHOLE CONTROL-PLANE SCRIPT, NOT THE exec LINE. Some flags are assembled into a shell variable
	// above it — CP_LICENCE carries the licence and seat-allocation stores — and expanded into the command. A
	// gate that read only the exec block reported those as missing, which is a false alarm, and a gate that
	// cries wolf is one a reader learns to skip.
	from := strings.Index(source, "\tcp := `#!/usr/bin/env sh")
	to := strings.Index(source, "\tedge := `#!/usr/bin/env sh")
	if from < 0 || to < 0 || to <= from {
		t.Fatal("launch.go no longer holds the control-plane and edge scripts as it did — this gate is " +
			"asserting nothing, which is worse than failing")
	}
	cp := source[from:to]
	if !strings.Contains(cp, `-control-plane`) {
		t.Fatal("the control-plane script does not start a control plane — this gate is asserting nothing")
	}

	// Each entry is a store whose contents an OPERATOR AUTHORS, and which therefore cannot live on whichever
	// node happened to serve the write. The reason is the test: if one of these ever becomes per-node again,
	// the symptom is a screen that answers differently on refresh.
	mustShare := map[string]string{
		"site-store":                          "a site's connectors, which the Sites page reads",
		"admin-auth-store":                    "who may sign in",
		"enrolled-inventory-store":            "which devices this deployment has admitted",
		"inspection-posture-store":            "what this deployment decrypts",
		"connector-registry-store":            "the connectors that have enrolled",
		"tenant-model-store":                  "the organizations themselves",
		"tenant-device-authority-store":       "each organization's device-identity CA",
		"transport-tenant-ca-registry":        "the customer-registered device CAs",
		"tenant-transport-authority-store":    "each organization's transport CA",
		"tenant-interception-authority-store": "each organization's interception authority",
		"agent-updates-store":                 "the releases this deployment publishes",
		"agent-rollout-store":                 "what each organization is told to run",
		"steer-exclusion-store":               "the apps an operator excluded from steering",
		"first-party-store":                   "first-party administrator accounts",
		"seat-allocation-store":               "how many devices each organization may enrol",
	}
	for flag, why := range mustShare {
		if !strings.Contains(cp, "-"+flag+"=postgres") {
			t.Errorf("the generated control plane does not set -%s=postgres — %s would live on whichever node "+
				"served the write, and the Console reads whichever node answers", flag, why)
		}
	}
}
