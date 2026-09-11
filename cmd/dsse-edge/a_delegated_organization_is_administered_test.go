package main

import (
	"os"
	"strings"
	"testing"
)

// ★★★ AN ORGANIZATION THE OPERATOR RUNS IS NOT "NOT WORKING YET" (2026-09-03, the operator's report that the
// Console did not match reality).
//
// The setup checklist marked "Their administrator" as blocking unconditionally, and the badge turns any
// blocking item into "· not working yet". Every organization in a managed deployment is run under a standing
// operator delegation and has no administrator of its own, so every one of them carried that badge for the
// whole of its life. The organization measured this way had enrolled a device, was inspecting its traffic
// under its own authority, and had completed an out-of-band step-up that day.
func TestADelegatedOrganizationIsNotReportedAsNotWorking(t *testing.T) {
	body, err := os.ReadFile("admin_organization_setup.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if !strings.Contains(src, "adminBlocks := true") || !strings.Contains(src, "if tenant.OperatorManaged {") {
		t.Fatal("the administrator item does not consider whether somebody is already running the " +
			"organization, so a delegated organization is badged as not working")
	}
	i := strings.Index(src, "adminBlocks := true")
	j := strings.Index(src[i:], `Key: "administrator"`)
	if j < 0 {
		t.Fatal("the administrator item no longer follows the decision")
	}
	if !strings.Contains(src[i:i+j], "adminBlocks = false") {
		t.Error("a delegated organization still blocks on having an administrator of its own")
	}
	if !strings.Contains(src[i:i+j+400], "Blocking: adminBlocks") {
		t.Error("the item is still hard-coded Blocking: true")
	}
	// It must still be ON the list: having an administrator of their own is what lets the organization stop
	// asking the operator for every change.
	if !strings.Contains(src, `Label: "Their administrator"`) {
		t.Error("the item was removed rather than made non-blocking — the question it asks is still real")
	}
}
