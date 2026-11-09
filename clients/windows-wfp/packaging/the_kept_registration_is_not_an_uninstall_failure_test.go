package packaging

import (
	"os"
	"strings"
	"testing"
)

// Found 2026-11-07, on every Windows uninstall of the 0.4.1 acceptance runs: the post-uninstall check counted
// the device identity under enroll\ as a failure. The uninstall keeps it on purpose, with the signed install
// profile, so that reinstalling for the same organization restores the device (windows-agent.md, "Removing
// it"), and no action could clear the failure — removing the device at the Console does not touch this disk.
// The same check then printed "left nothing behind" whenever it passed, which is not what the uninstall does.
func afterUninstallSection(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("verify-windows-install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(string(raw), "\r\n", "\n")
	start := strings.Index(script, `Write-Host "== after uninstall: what is left on this machine =="`)
	end := strings.Index(script, `Write-Host "== 1. installed files =="`)
	if start < 0 || end < 0 || end < start {
		t.Fatal("the after-uninstall section is not where this test looks for it")
	}
	return script[start:end]
}

func TestTheRegistrationTheUninstallKeepsIsReportedNotFailed(t *testing.T) {
	section := afterUninstallSection(t)
	for _, line := range strings.Split(section, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "bad ") && (strings.Contains(trimmed, "enroll") ||
			strings.Contains(trimmed, "install-profile.json") || strings.Contains(trimmed, "profile_signing_key.txt")) {
			t.Errorf("the post-uninstall check fails on what the uninstall keeps on purpose: %s", trimmed)
		}
	}
	if !strings.Contains(section, `enroll\device.key.dpapi`) {
		t.Error("the kept device identity is no longer reported at all — it is live at the deployment until an " +
			"administrator removes the device, and the reader has to be told where it is")
	}
	if !strings.Contains(section, "stays enrolled at the deployment until an administrator removes the device") {
		t.Error("the report no longer says the kept identity is still enrolled at the deployment")
	}
}

func TestAPassThatKeptTheRegistrationDoesNotSayNothingWasLeft(t *testing.T) {
	section := afterUninstallSection(t)
	nothing := strings.Index(section, "the uninstall left nothing behind")
	keptPass := strings.Index(section, "it kept the registration listed above on purpose")
	if nothing < 0 || keptPass < 0 {
		t.Fatal("the two pass lines are not both present")
	}
	guard := strings.Index(section, "if ($kept.Count -gt 0) {\n      Write-Host \"verify-windows-install: PASS")
	if guard < 0 || !(guard < keptPass && keptPass < nothing) {
		t.Error("\"left nothing behind\" is printed without first asking whether the registration was kept")
	}
	// Deleting the kept files is the reader's decision, for a PC leaving DSSE or moving deployment — not a step
	// to run after every uninstall.
	if strings.Contains(section, "note \"then: Remove-Item -Recurse") &&
		!strings.Contains(section, "when this PC leaves DSSE, or before installing it for another deployment or organization") {
		t.Error("the check tells the reader to delete the kept registration unconditionally")
	}
}
